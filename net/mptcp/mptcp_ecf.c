/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */
/* ytxing: some symbol changes
 * 1. ECF tp->srtt => tp->srtt_us 
 * 2. snd_cwnd_before_idle_restart undefined
 * 3. tp->rttvar => tp->rttvar_us
 */
#include <linux/bug.h>
#include <linux/module.h>
#include <net/mptcp.h>
#include <trace/events/tcp.h>

static LIST_HEAD(mptcp_sched_list);

static unsigned int r_beta __read_mostly = 4; // beta = 1/r_beta = 0.25
module_param(r_beta, int, 0644);
MODULE_PARM_DESC(r_beta, "beta for ECF");

struct ecf_sched_priv {
	u32 last_rbuf_opti; // for default scheduler

	u32 switching_margin; // this is "waiting" in algorithm description in the draft
};

static struct ecf_sched_priv *ecf_sched_get_priv(const struct tcp_sock *tp)
{
	return (struct ecf_sched_priv *)&tp->mptcp->mptcp_sched[0];
}


/* estimate number of segments currently in flight + unsent in
 * the subflow socket.
 */
static int mptcp_subflow_queued(struct sock *sk, u32 max_tso_segs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int queued;

	/* estimate the max number of segments in the write queue
	 * this is an overestimation, avoiding to iterate over the queue
	 * to make a better estimation.
	 * Having only one skb in the queue however might trigger tso deferral,
	 * delaying the sending of a tso segment in the hope that skb_entail
	 * will append more data to the skb soon.
	 * Therefore, in the case only one skb is in the queue, we choose to
	 * potentially underestimate, risking to schedule one skb too many onto
	 * the subflow rather than not enough.
	 */
	if (sk->sk_write_queue.qlen > 1)
		queued = sk->sk_write_queue.qlen * max_tso_segs;
	else
		queued = sk->sk_write_queue.qlen;

	return queued + tcp_packets_in_flight(tp);
}

static bool mptcp_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return true;
		else if (tp->snd_una != tp->high_seq)
			return true;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return true;
	}

	mss_now = tcp_current_mss(sk);

	/* Not even a single spot in the cwnd */
	if (mptcp_subflow_queued(sk, tcp_tso_segs(sk, mss_now)) >= tp->snd_cwnd)
		return true;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return true;

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return true;

	return false;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
static struct sock
*get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test, bool *force)
{
	struct sock *bestsk = NULL;
	u32 min_srtt = 0xffffffff;
	bool found_unused = false;
	bool found_unused_una = false;
	struct mptcp_tcp_sock *mptcp;

	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(sk);
		bool unused = false;

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp))
			continue;

		if (!mptcp_dont_reinject_skb(tp, skb))
			unused = true;
		else if (found_unused)
			/* If a unused sk was found previously, we continue -
			 * no need to check used sks anymore.
			 */
			continue;

		if (mptcp_is_def_unavailable(sk))
			continue;

		if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			if (unused)
				found_unused_una = true;
			continue;
		}

		if (unused) {
			if (!found_unused) {
				/* It's the first time we encounter an unused
				 * sk - thus we reset the bestsk (which might
				 * have been set to a used sk).
				 */
				min_srtt = 0xffffffff;
				bestsk = NULL;
			}
			found_unused = true;
		}

		if (tp->srtt_us < min_srtt) {
			min_srtt = tp->srtt_us;
			bestsk = sk;
		}
	}

	if (bestsk) {
		/* The force variable is used to mark the returned sk as
		 * previously used or not-used.
		 */
		if (found_unused)
			*force = true;
		else
			*force = false;
	} else {
		/* The force variable is used to mark if there are temporally
		 * unavailable not-used sks.
		 */
		if (found_unused_una)
			*force = true;
		else
			*force = false;
	}

	return bestsk;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
struct sock *default_get_available_subflow(struct sock *meta_sk, struct sk_buff *skb,
				   bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	bool looping = false, force;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		struct mptcp_tcp_sock *mptcp;

		mptcp_for_each_sub(mpcb, mptcp) {
			sk = mptcp_to_sock(mptcp);

			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* Find the best subflow */
restart:
	sk = get_subflow_from_selectors(mpcb, skb, &subflow_is_active,
					zero_wnd_test, &force);
	if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
		return sk;

	sk = get_subflow_from_selectors(mpcb, skb, &subflow_is_backup,
					zero_wnd_test, &force);
	if (!force && skb) {
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
		TCP_SKB_CB(skb)->path_mask = 0;

		if (!looping) {
			looping = true;
			goto restart;
		}
	}
	return sk;
}

/* 
 * ytxing: this is the main function of ecf.
 */
static struct sock *ecf_get_available_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL;
	u32 sub_sndbuf = 0;
	u32 sub_packets_out = 0;
	u32 min_rtt = 0xffffffff;
	struct ecf_sched_priv *esp = ecf_sched_get_priv(tcp_sk(meta_sk));

	struct tcp_sock *tp;
	struct sock *fastest_sk = NULL; // ylim
	struct mptcp_tcp_sock *mptcp;

	// ylim: moved from default_get_available_subflow
	/* if there is only one subflow, bypass the scheduling function */
	/* ytxing: maybe not necessary, delete? TODO */
	// if (mpcb->cnt_subflows == 1) {
	// 	bestsk = (struct sock *)mpcb->connection_list;
	// 	if (!mptcp_is_available(bestsk, skb, zero_wnd_test))
	// 		bestsk = NULL;
	// 	return bestsk;
	// }

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		struct mptcp_tcp_sock *mptcp;

		mptcp_for_each_sub(mpcb, mptcp) {
			sk = mptcp_to_sock(mptcp);

			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	// ylim: First, find fastest sk
	mptcp_for_each_sub(mpcb, mptcp) {
		sk = mptcp_to_sock(mptcp);
		tp = tcp_sk(sk);
		if(sk != meta_sk) {
			sub_sndbuf += ( (u32) sk->sk_wmem_queued );
			sub_packets_out += tp->packets_out;
		}

		if(tp->mptcp->fully_established && tp->srtt_us < min_rtt) {
			fastest_sk = sk;
			min_rtt = tp->srtt_us;
		}
	}

	// ylim: at this point, fastest_sk MUST be not NULL
	// ylim: observed kernel panic due to NULL pointer. Checking fastest_sk for safety
	bestsk = NULL;
	if(unlikely(fastest_sk == NULL)) {
		mptcp_debug("ylim: fastest_sk is NULL?");
		// ylim: why? this should never happen
	} else {
		// ylim: if fastest is available, go with it!
		tp = tcp_sk(fastest_sk);
		if( !(tp->mptcp->rcv_low_prio || tp->mptcp->low_prio) ) {
			if( mptcp_is_available(fastest_sk, skb, zero_wnd_test) ) {
				if( !mptcp_dont_reinject_skb(tp, skb) ) {
					u32 mss = ( (u32) tcp_current_mss(fastest_sk) );

					u32 sndbuf_meta = ( (u32) meta_sk->sk_wmem_queued );
					u32 sndbuf_minus = sub_sndbuf +  
								(tcp_sk(meta_sk)->packets_out > sub_packets_out ? tcp_sk(meta_sk)->packets_out - sub_packets_out : 0) * mss;
					u32 sndbuf = sndbuf_meta > sndbuf_minus ? sndbuf_meta - sndbuf_minus : 0; // can be smaller? anyway for safety

					u32 cwnd_f = max(tcp_sk(fastest_sk)->snd_cwnd, tcp_sk(fastest_sk)->snd_cwnd_before_idle_restart);
					// u32 cwnd_f = tcp_sk(fastest_sk)->snd_cwnd;
					u32 srtt_f = tcp_sk(fastest_sk)->srtt_us >> 3;
					u32 rttvar_f = tcp_sk(fastest_sk)->rttvar_us >> 1;
				
					bestsk = fastest_sk;

					mptcp_debug("%s: %pI4:%d -> %pI4:%d, fastest is used %u %u %u %u %u\n",
					    __func__ , 
					    &((struct inet_sock *) bestsk )->inet_saddr,
					    ntohs(((struct inet_sock *) bestsk )->inet_sport),
					    &((struct inet_sock *) bestsk )->inet_daddr,
					    ntohs(((struct inet_sock *) bestsk )->inet_dport),
					    sndbuf, srtt_f, rttvar_f, cwnd_f, mss );

					if(tp->snd_cwnd > tp->snd_cwnd_before_idle_restart) {
						tp->snd_cwnd_before_idle_restart = 0;
					}
				}
			}
		}
	}

	// ylim: fastest is not available, check others
	if(bestsk == NULL) {
		// ylim: call default scheduler. Some redundant checkings at the beginning are removed in default_get_available_subflow.
		bestsk = default_get_available_subflow(meta_sk, skb, zero_wnd_test);
		if( unlikely(fastest_sk == bestsk) ) {
			// nothing to do
		} else {
			if(bestsk != NULL && fastest_sk != NULL) {
				u32 mss = ( (u32) tcp_current_mss(bestsk) );

				u32 sndbuf_meta = ( (u32) meta_sk->sk_wmem_queued );
				u32 sndbuf_minus = sub_sndbuf +  
							(tcp_sk(meta_sk)->packets_out > sub_packets_out ? tcp_sk(meta_sk)->packets_out - sub_packets_out : 0) * mss;
				u32 sndbuf = sndbuf_meta > sndbuf_minus ? sndbuf_meta - sndbuf_minus : 0; // can be smaller? anyway for safety

				u32 cwnd_f = max( tcp_sk(fastest_sk)->snd_cwnd, tcp_sk(fastest_sk)->snd_cwnd_before_idle_restart );
				// u32 cwnd_f = tcp_sk(fastest_sk)->snd_cwnd;
				u32 srtt_f = tcp_sk(fastest_sk)->srtt_us >> 3;
				u32 rttvar_f = tcp_sk(fastest_sk)->rttvar_us >> 1;

				u32 cwnd_s = max( tcp_sk(bestsk)->snd_cwnd, tcp_sk(bestsk)->snd_cwnd_before_idle_restart );
				// u32 cwnd_s = tcp_sk(bestsk)->snd_cwnd;
				u32 srtt_s = tcp_sk(bestsk)->srtt_us >> 3;
				u32 rttvar_s = tcp_sk(bestsk)->rttvar_us >> 1;

				// to avoid overflow, using u64
				u64 lhs, rhs;
				u32 delta;
				
				// we have something to send.
				// at least one time tx over fastest subflow is required
				u32 x_f = sndbuf > cwnd_f * mss ? sndbuf : cwnd_f * mss;

				delta = max(rttvar_f, rttvar_s);
				lhs = srtt_f * (x_f + cwnd_f * mss);
				rhs =  cwnd_f * mss * (srtt_s + delta);  

				if( r_beta * lhs < r_beta * rhs + esp->switching_margin * rhs ) {
					u32 x_s = sndbuf > cwnd_s * mss ? sndbuf : cwnd_s * mss;
					u64 lhs_s = srtt_s * x_s;
					u64 rhs_s = cwnd_s * mss * (2 * srtt_f + delta);  

					if( lhs_s < rhs_s ) {
						mptcp_debug("%s: %pI4:%d -> %pI4:%d, seemed slower but faster, %u %u %u %u %u %u %u %u %llu %llu\n",
						    __func__ , 
						    &((struct inet_sock *) bestsk )->inet_saddr,
						    ntohs(((struct inet_sock *) bestsk )->inet_sport),
						    &((struct inet_sock *) bestsk )->inet_daddr,
						    ntohs(((struct inet_sock *) bestsk )->inet_dport),
						    sndbuf, srtt_f, srtt_s, rttvar_f, rttvar_s, cwnd_f, cwnd_s, mss, lhs_s, rhs_s );
						if(tcp_sk(bestsk)->snd_cwnd > tcp_sk(bestsk)->snd_cwnd_before_idle_restart) {
							tcp_sk(bestsk)->snd_cwnd_before_idle_restart = 0;
						} // af
					} else {
						mptcp_debug("%s: %pI4:%d -> %pI4:%d, too slower than fastest, %u %u %u %u %u %u %u %u %llu %llu\n",
						    __func__ , 
						    &((struct inet_sock *) bestsk )->inet_saddr,
						    ntohs(((struct inet_sock *) bestsk )->inet_sport),
						    &((struct inet_sock *) bestsk )->inet_daddr,
						    ntohs(((struct inet_sock *) bestsk )->inet_dport),
						    sndbuf, srtt_f, srtt_s, rttvar_f, rttvar_s, cwnd_f, cwnd_s, mss, lhs, rhs );

						bestsk = NULL;
						esp->switching_margin = 1;
					}
				} else {
					mptcp_debug("%s: %pI4:%d -> %pI4:%d, use slower one, %u %u %u %u %u %u %u %u %llu %llu\n",
					    __func__ , 
					    &((struct inet_sock *) bestsk )->inet_saddr,
					    ntohs(((struct inet_sock *) bestsk )->inet_sport),
					    &((struct inet_sock *) bestsk )->inet_daddr,
					    ntohs(((struct inet_sock *) bestsk )->inet_dport),
					    sndbuf, srtt_f, srtt_s, rttvar_f, rttvar_s, cwnd_f, cwnd_s, mss, lhs, rhs);
					if(tcp_sk(bestsk)->snd_cwnd > tcp_sk(bestsk)->snd_cwnd_before_idle_restart) {
						tcp_sk(bestsk)->snd_cwnd_before_idle_restart = 0;
					}
					esp->switching_margin = 0;
				}
			}
		}
	}

	return bestsk;
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_tcp_sock *mptcp;
	struct sk_buff *skb_head;
	struct ecf_sched_priv *def_p = ecf_sched_get_priv(tp);

	meta_sk = mptcp_meta_sk(sk);
	skb_head = tcp_rtx_queue_head(meta_sk);

	if (!skb_head)
		return NULL;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
		goto retrans;

	/* Only penalize again after an RTT has elapsed */
	if (tcp_jiffies32 - def_p->last_rbuf_opti < usecs_to_jiffies(tp->srtt_us >> 3))
		goto retrans;

	/* Half the cwnd of the slow flows */
	mptcp_for_each_sub(tp->mpcb, mptcp) {
		struct tcp_sock *tp_it = mptcp->tp;

		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt_us < tp_it->srtt_us && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				u32 prior_cwnd = tp_it->snd_cwnd;

				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

				/* If in slow start, do not reduce the ssthresh */
				if (prior_cwnd >= tp_it->snd_ssthresh)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				def_p->last_rbuf_opti = tcp_jiffies32;
			}
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		bool do_retrans = false;
		mptcp_for_each_sub(tp->mpcb, mptcp) {
			struct tcp_sock *tp_it = mptcp->tp;

			if (tp_it != tp &&
			    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
				if (tp_it->snd_cwnd <= 4) {
					do_retrans = true;
					break;
				}

				if (4 * tp->srtt_us >= tp_it->srtt_us) {
					do_retrans = false;
					break;
				} else {
					do_retrans = true;
				}
			}
		}

		if (do_retrans && mptcp_is_available(sk, skb_head, false)) {
			trace_mptcp_retransmit(sk, skb_head);
			return skb_head;
		}
	}
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_next_segment(struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk;

			/* meta is send buffer limited */
			tcp_chrono_start(meta_sk, TCP_CHRONO_SNDBUF_LIMITED);

			subsk = get_available_subflow(meta_sk, NULL, false);
			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
			else
				tcp_chrono_start(subsk,
						 TCP_CHRONO_SNDBUF_LIMITED);
		}
	}
	return skb;
}

static struct sk_buff *mptcp_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	u32 max_len, gso_max_segs, max_segs, max_tso_segs, window;
	struct tcp_sock *subtp;
	int queued;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		/* an active flow is selected, but segment will not be sent due
		 * to no more space in send window
		 * this means the meta is receive window limited
		 * the subflow might also be, if we have nothing to reinject
		 */
		tcp_chrono_start(meta_sk, TCP_CHRONO_RWND_LIMITED);
		skb = mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

	if (!*reinject) {
		/* this will stop any other chronos on the meta */
		tcp_chrono_start(meta_sk, TCP_CHRONO_BUSY);
	}

	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;

	max_tso_segs = tcp_tso_segs(*subsk, tcp_current_mss(*subsk));
	queued = mptcp_subflow_queued(*subsk, max_tso_segs);

	/* this condition should already have been established in
	 * mptcp_is_temp_unavailable when selecting available flows
	 */
	WARN_ONCE(subtp->snd_cwnd <= queued, "Selected subflow no cwnd room");

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;

	max_segs = min_t(unsigned int, subtp->snd_cwnd - queued, gso_max_segs);
	if (!max_segs)
		return NULL;

	/* if there is room for a segment, schedule up to a complete TSO
	 * segment to avoid TSO splitting. Even if it is more than allowed by
	 * the congestion window.
	 */
	max_segs = max_t(unsigned int, max_tso_segs, max_segs);

	max_len = min(mss_now * max_segs, skb->len);

	window = tcp_wnd_end(subtp) - subtp->write_seq;

	/* max_len now also respects the announced receive-window */
	max_len = min(max_len, window);

	*limit = max_len;

	return skb;
}

static void ecf_sched_init(struct sock *sk)
{
	struct ecf_sched_priv *esp = ecf_sched_get_priv(tcp_sk(sk));

	esp->last_rbuf_opti = tcp_jiffies32;
	esp->switching_margin = 0;
}

struct mptcp_sched_ops mptcp_sched_ecf = {
	.get_subflow = ecf_get_available_subflow,
	.next_segment = mptcp_next_segment,
	.init = ecf_sched_init,
	.name = "ecf",	
	.owner = THIS_MODULE,
};

static int __init ecf_register(void)
{
	BUILD_BUG_ON(sizeof(struct ecf_sched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_ecf))
		return -1;

	return 0;
}

static void ecf_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_ecf);
}

module_init(ecf_register);
module_exit(ecf_unregister);

MODULE_AUTHOR("Yeon-sup Lim");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ECF");
MODULE_VERSION("0.95.2");
