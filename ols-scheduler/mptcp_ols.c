/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>
#include <asm/div64.h>
#define necessary_rate 10000000 >> 3
static bool USE_OVERLAP __read_mostly = 1;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 0, the scheduler will not send redundant data");

struct olssched_priv {
	
	/* The skb or NULL */
	struct sk_buff *skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 skb_end_seq;

	u32 red_quota;
	u32 new_quota;
}
struct olssched_priv_out {
	/* Limited by MPTCP_SCHED_SIZE */
	struct olssched_priv *real_priv;
};

/* Returns the socket data from a given subflow socket */
static struct olssched_priv *olssched_get_priv(struct tcp_sock *tp)
{
	struct olssched_priv_out *ols_p = &tp->mptcp->mptcp_sched[0];
	struct olssched_priv *real_priv = ols_p->real_priv;
	return real_priv;
}

/* Struct to store the data of the control block */
struct olssched_cb {
	/* The next subflow where a skb should be sent or NULL */
	//u32 redundant_flag;
	struct tcp_sock *previous_tp;//ytxing: previous_tp that need help
};

/* Returns the control block data from a given meta socket */
static struct olssched_cb *olssched_get_cb(struct tcp_sock *tp)
{
	return (struct olssched_cb *)&tp->mpcb->mptcp_sched[0];
}

/* Corrects the stored skb pointers if they are invalid */
static void olssched_correct_skb_pointers(struct sock *meta_sk,
					  struct olssched_priv *ols_p)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	if (ols_p->skb &&
	    (before(ols_p->skb_end_seq, meta_tp->snd_una) ||
	     after(ols_p->skb_end_seq, meta_tp->snd_nxt))){
		 	ols_p->skb = NULL;
		 }
}
/* If the sub-socket sk available to send the skb? */
static bool mptcp_rr_is_available(const struct sock *sk, const struct sk_buff *skb,
				  bool zero_wnd_test, bool cwnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int space, in_flight;

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return false;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return false;

	if (tp->pf)
		return false;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return false;
		else if (tp->snd_una != tp->high_seq)
			return false;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return false;
	}

	if (!cwnd_test)//ytxing NOTICE
		goto zero_wnd_test;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return false;

zero_wnd_test:
	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return false;

	return true;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_rr_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}					  
/*zy*/
/*to send this skb we need how many times slowstart transfer*/
static u32  count_round_in_ss(const struct sock *subsk, const struct sk_buff *skb)
{
    struct tcp_sock *subtp = tcp_sk(subsk);
	u32 round_ss = 1;
	u32 i, total_cwnd, cwnd_now,send_skb, mss_now;
	cwnd_now = subtp->snd_cwnd;
	if(cwnd_now == 0){
		//mptcp_debug(KERN_DEBUG "zy: ss_cwnd = 0\n");
		return 0;
	}
	mss_now = tcp_current_mss(subsk);
	send_skb = subtp->write_seq+ min(skb->len, mss_now) - subtp->snd_nxt;
	
	total_cwnd = subtp->snd_cwnd;
	if (send_skb < cwnd_now * mss_now){
		mptcp_debug(KERN_DEBUG "zy:can send this in one ss round");
		return round_ss;
	}
	while (total_cwnd < subtp->snd_ssthresh && (total_cwnd - cwnd_now) * mss_now < send_skb ){
		total_cwnd = (total_cwnd << 1);
		round_ss += 1;
	}
		
	/*reach snd_ssthresh, can't send  out this skb*/
	if((total_cwnd - cwnd_now) * mss_now < send_skb && total_cwnd >= subtp->snd_ssthresh){
		//mptcp_debug(KERN_DEBUG "zy: round ss:%u",round_ss);
		//mptcp_debug(KERN_DEBUG "zy: reach snd_ssthresh, can't send  out this skb,total_cwnd%u ssthresh%u cwnd%u\n", total_cwnd, subtp->snd_ssthresh, cwnd_now);
		return round_ss;
	}
	/*in slowstart can send out this skb*/
	else if ((total_cwnd - cwnd_now) * mss_now >= send_skb){
		//mptcp_debug(KERN_DEBUG "zy: round ss:%u",round_ss);
		//mptcp_debug(KERN_DEBUG "zy: dont reach snd_ssthresh, can send  out this skb,total_cwnd%u ssthresh%u cwnd%u\n round", total_cwnd, subtp->snd_ssthresh, cwnd_now);
		return round_ss;
	}
		
}
					  
//zy count round in ca
static u32 count_round_in_ca(struct sock *subsk, struct sk_buff *skb, u32 temp_cwnd)
{
    struct tcp_sock *subtp = tcp_sk(subsk);
	u32 send_skb,i , mss_now, round_ss, total_cwnd;
	u32 round_ca = 1;
	mss_now = tcp_current_mss(subsk);
	total_cwnd =  subtp->snd_cwnd;
	if(total_cwnd == 0){
		//mptcp_debug(KERN_DEBUG "zy: ca_cwnd = 0\n");
		return 0;
		}
	if(subtp->snd_cwnd >= subtp->snd_ssthresh)
	    send_skb = subtp->write_seq+ min(skb->len, mss_now) - subtp->snd_nxt;
	else if (subtp->snd_cwnd < subtp->snd_ssthresh){
		round_ss = count_round_in_ss(subsk,skb);
		for(i = 0; i < round_ss; i += 1){
				total_cwnd = total_cwnd << 1;
		}
		send_skb = subtp->write_seq+ min(skb->len, mss_now) - subtp->snd_nxt-((total_cwnd - subtp->snd_cwnd) * mss_now);
	}
	if(round_ca ==1 && temp_cwnd * mss_now < send_skb)
		round_ca += 1;
	if (round_ca >= 2){
		while((round_ca * temp_cwnd + (round_ca * (round_ca-1)) >> 1)  * mss_now < send_skb){
			round_ca = round_ca + 1;
		}
	}
	//mptcp_debug(KERN_DEBUG "zy: round ca:%u",round_ca);
	//mptcp_debug(KERN_DEBUG "zy: dont reach snd_ssthresh, can send  out this skb,total_cwnd%u ssthresh%u cwnd%u\n", total_cwnd, subtp->snd_ssthresh, temp_cwnd);
	return round_ca;
}

// zy naive schedule
/*u32 get_transfer_time(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 srtt = tp->srtt_us >> 1;
	u32 send_cwnd, send_skb, transfer_time, j;
	u32 in_flight, space_cwnd, mss_now;
	send_cwnd = tp->snd_cwnd;
	send_skb = tp->write_seq+ min(skb->len, mss_now) - tp->snd_nxt;
	in_flight = tcp_packets_in_flight(tp);
	if(send_cwnd > in_flight)
		space_cwnd = (tp->snd_cwnd - in_flight) * tp->mss_cache;
	else 
		space_cwnd = 0;
	mss_now = tcp_current_mss(sk);
	transfer_time = 0;
	if(add_delta)
		srtt += tp->mdev_max_us;
	if(!send_cwnd)
		return 0;
	else if(space_cwnd > send_skb){
		transfer_time = (srtt << 1);
		return transfer_time;
	}
	j = 0;
	while(send_cwnd * mss_now < (send_skb-space_cwnd) && (send_skb - space_cwnd) > 0){
		send_skb -= send_cwnd * mss_now;
		j += 1;
	}
		transfer_time = (j * 2 + 1) * (srtt << 1)
		
	//u32 transfer_time = srtt;
	//TODO
	return transfer_time;

}
*///ZZZZZZZZ

// static u32 get_transfer_time(struct sock* subsk, struct sk_buff *skb)
// {   
//     struct tcp_sock *subtp = tcp_sk(subsk);
//     u32 transfer_time = 0;
// 	u32 mss_now, space_cwnd, in_flight, i, send_skb, total_cwnd,cwnd_now, rtt;
// 	u32 round_in_ss=1, round_in_ca=1;
// 	rtt = subtp->srtt_us;
// 	//mptcp_debug(KERN_DEBUG "zy: this sk%u , this sk_rtt%u\n",subsk, rtt >> 3);
// 	if(!rtt)
// 		return 0;
// 	if(add_delta)
// 		rtt += subtp->mdev_us;

// 	total_cwnd = subtp->snd_cwnd;
// 	cwnd_now = subtp->snd_cwnd;
// 	mss_now = tcp_current_mss(subsk);
// 	send_skb = subtp->write_seq+ min(skb->len, mss_now) - subtp->snd_nxt;
// 	in_flight = tcp_packets_in_flight(subtp);
// 	space_cwnd = (subtp->snd_cwnd - in_flight) * subtp->mss_cache;
// 	if (send_skb <= space_cwnd){
// 		mptcp_debug(KERN_DEBUG "zy:[sk,%u,][cwnd*mss,%u,Bytes][queue,%u,Bytes][transfer_time,%u,us] skb < space",subsk, subtp->snd_cwnd * mss_now, send_skb, transfer_time >> 3); 
// 		return (rtt >> 1);
// 	}
// 	else
// 		if(subtp->snd_cwnd < subtp->snd_ssthresh){
// 			round_in_ss = count_round_in_ss(subsk, skb);
// 			if(round_in_ss == 0){
// 				//mptcp_debug(KERN_DEBUG "zy:round_in_ss = 0\n");
// 				return 0;
// 			}
				
// 			for(i=0;i<round_in_ss;i++)
// 				total_cwnd = total_cwnd << 1;
// 			if(round_in_ss == 1)
// 				transfer_time += rtt >> 1;
// 			else if(round_in_ss > 1)
// 				transfer_time += rtt * (round_in_ss-1) + (rtt >> 1);
// 			if((total_cwnd - cwnd_now) * mss_now > send_skb){
// 				mptcp_debug(KERN_DEBUG "zy:[sk,%u,][cwnd*mss,%u,Bytes][queue,%u,Bytes][transfer_time,%u,us][round_in_ss,%u,] ss can send",subsk, subtp->snd_cwnd * mss_now, send_skb, transfer_time >> 3, round_in_ss); 
//                			return transfer_time;
// 			}
// 			else if((total_cwnd - cwnd_now) * mss_now < send_skb){
// 				cwnd_now = subtp->snd_ssthresh;
// 				round_in_ca = count_round_in_ca(subsk, skb, cwnd_now);
// 				if(round_in_ca == 0){
// 				//mptcp_debug(KERN_DEBUG "zy:round_in_ca = 0\n");
// 				return 0;
// 				}
// 				if(round_in_ca == 1)
// 					transfer_time += rtt >> 1;
// 				else if(round_in_ca > 1)
// 					transfer_time += rtt * (round_in_ca-1) + (rtt >> 1) ;
// 				mptcp_debug(KERN_DEBUG "zy:[sk,%u,][cwnd*mss,%u,Bytes][queue,%u,Bytes][transfer_time,%u,us][round_in_ss,%u,][round_in_ca,%u,] ss can't send",subsk, subtp->snd_cwnd * mss_now, send_skb, transfer_time >> 3, round_in_ss, round_in_ca); 
// 				return transfer_time;
// 			}
			
// 		}
// 		else if(subtp->snd_cwnd >= subtp->snd_ssthresh){
// 			round_in_ca = count_round_in_ca(subsk, skb, cwnd_now);
// 			if(round_in_ca == 1)
// 				transfer_time += rtt >> 1;
// 			else if(round_in_ca > 1)
// 				transfer_time += rtt * (round_in_ca-1) + (rtt >> 1);
// 		mptcp_debug(KERN_DEBUG "zy:[sk,%u,][cwnd*mss,%u,Bytes][queue,%u,Bytes][transfer_time,%u,us][round_in_ca,%u,] ca can send",subsk, subtp->snd_cwnd * mss_now, send_skb, transfer_time >> 3,  round_in_ca); 
// 		    return transfer_time;
// 		}
// }

static u32 get_transfer_time(struct sock* sk, struct sk_buff *skb, bool add_delta)
{   
	/* can be simply queued/pacing_rate? */
	struct tcp_sock *tp = tcp_sk(sk);
	u64 transfer_time;
	u64 expand_factor;
	u32 rate;
	u32 unsent_bytes = tp->write_seq - tp->snd_nxt + skb->len;

	/* here we trust the sk->sk_pacing_rate, NO? */
	if (unlikely(!sk->sk_pacing_rate))
		return 0;
	rate = sk->sk_pacing_rate;
	transfer_time = div_u64((u64)unsent_bytes * USEC_PER_SEC, rate); /* us */
	if (!add_delta || !tp->srtt_us || !tp->rttvar_us)
		return transfer_time;
	expand_factor = tp->srtt_us + tp->rttvar_us << 3; /* ytxing: maybe add a cap for this expand factor? TODO */
	do_div(expand_factor, tp->srtt_us);
	transfer_time *= expand_factor;
	return transfer_time;
}

/* zy
 * Return the subflow with the shortest transfer time.
 * May be cwnd-limited but fully established.
 */	
static struct sock *get_fastest_subflow(struct sock *meta_sk,
					     struct sk_buff *skb, bool *force)
{
	//mptcp_debug(KERN_DEBUG "ytxing: ***get_fastest_subflow***\n");
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct mptcp_tcp_sock *mptcp;
	struct tcp_sock *best_tp, *tp_t;
	u32 min_transfer_time = 0xffffffff;
	u32 transfer_time = 0;
	struct sock *best_sk = NULL, *sk_t = NULL;

	mptcp_for_each_sub(mpcb, mptcp) {
		tp_t = mptcp->tp;
		sk_t = mptcp_to_sock(mptcp);
		if (mptcp_is_def_unavailable(sk_t))
			continue;

		transfer_time = get_transfer_time(sk_t, skb, false);
		mptcp_debug(KERN_DEBUG "zy:[sk,%u,][transfer_time,%u,us]", sk_t, transfer_time >> 3);

		if(!transfer_time){
			//mptcp_debug(KERN_DEBUG "zy: sk%u has 0 transfer_time\n", sk_t);
			continue;
		}
		if(transfer_time < min_transfer_time){
			min_transfer_time = transfer_time;
			best_sk = sk_t;
			//mptcp_debug(KERN_DEBUG "ytxing: sk%u has transfer_time%u\n", best_sk, min_transfer_time >> 3);
		}
	}
	//if(best_sk){
		//mptcp_debug(KERN_DEBUG "ytxing: best_sk%u has min_transfer_time%u\n", best_sk, min_transfer_time >> 3);
	//}
	//mptcp_debug(KERN_DEBUG "ytxing: ---get_fastest_subflow---\n");
	return best_sk;
}

static struct sock *get_second_subflow(struct sock *meta_sk,
					     struct sk_buff *skb)
{
	//mptcp_debug(KERN_DEBUG "ytxing: ***get_second_subflow***\n");
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct mptcp_tcp_sock *mptcp;
	struct tcp_sock *best_tp, *tp_t;
	u32 min_transfer_time = 0xffffffff;
	u32 transfer_time = 0;
	//u32 in_flight, space;
	struct sock *second_sk = NULL, *sk_t = NULL;
	struct sock *best_sk = get_fastest_subflow(meta_sk, skb);
	
	mptcp_for_each_sub(mpcb, mptcp) {
		tp_t = mptcp->tp;
		sk_t = mptcp_to_sock(mptcp);
		if (mptcp_is_def_unavailable(sk_t))
			continue;
		transfer_time = get_transfer_time(sk_t, skb, false);

		if(!transfer_time)
			continue;
		
		if(best_sk == sk_t)
			continue;

		if(transfer_time < min_transfer_time){
			min_transfer_time = transfer_time;
			second_sk = sk_t;
		}
	}
	//if(second_sk){
		//mptcp_debug(KERN_DEBUG "ytxing: second_sk%u has min_transfer_time%u\n", second_sk, min_transfer_time >> 3);
	//}
	//mptcp_debug(KERN_DEBUG "ytxing: ---get_second_subflow---\n");
	return second_sk;
}

static void ols_set_quota(struct sock *meta_sk, struct sock *subsk)
{
	struct mptcp_tcp_sock *mptcp;
	struct tcp_sock *subtp = tcp_sk(subsk);
	struct olssched_priv *ols_p = olssched_get_priv(subtp);
	u64 sk_rate, total_rate = 0, new_rate = 0;
	u64 new_quota_t;

	mptcp_for_each_sub(tcp_sk(meta_sk)->mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(sk);
		if (!mptcp_sk_can_send(sk))
			continue;

		/* Do not consider subflows without a RTT estimation yet
		 * otherwise this_rate >>> rate.
		 */
		
		if (unlikely(!tp->srtt_us || !sk->sk_pacing_rate))
			continue;

		// div64_u64((u64)mss_now * (USEC_PER_SEC << 3) * tp->snd_cwnd, (u64)tp->srtt_us);
		total_rate += sk->sk_pacing_rate;
	}

	// sk_rate = div64_u64((u64)mss_now * (USEC_PER_SEC << 3) * subtp->snd_cwnd, (u64)subtp->srtt_us);
	sk_rate = subsk->sk_pacing_rate;

	if(necessary_rate < (total_rate - sk_rate)){
		new_rate = 0;
	}
	else{
		new_rate = necessary_rate - (total_rate - sk_rate);
	
	}
	new_quota_t = subtp->snd_cwnd * new_rate;
	new_quota_t = div64_u64(new_quota_t, sk_rate);
	ols_p->new_quota = min((u32)new_quota_t, subtp->snd_cwnd);
	ols_p->red_quota = subtp->snd_cwnd - ols_p->new_quota;
}

/* ytxing: ols_check_quota return false when the sk is trying to send to much redundant data */
static bool ols_check_quota(struct sock *meta_sk, struct sock *sk, bool new_flags){
	struct tcp_sock *tp = tcp_sk(sk);
	struct olssched_priv *ols_p = olssched_get_priv(tp);
	if(ols_p->red_quota == 0 && ols_p->new_quota == 0){
		ols_set_quota(meta_sk, sk);
	}
	if(new_flags) {
		if(ols_p->new_quota)
			ols_p->new_quota -= 1;
		else 
			ols_p->red_quota -= 1;
	} 
	else {
		if(ols_p->red_quota)
			ols_p->red_quota -= 1;
		else{
			mptcp_debug(KERN_DEBUG "no enough re_cwnd,[sk,%u,]\n",sk);
			return false;
		}
	}
	mptcp_debug(KERN_DEBUG "ols_check_quota sk%u new_flag%u\n",sk, new_flags);
	return true;
}

/* estimate number of segments currently in flight + unsent in
 * the subflow socket.
 *
 * ytxing: a copy from mptcp_sched.c
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

bool subsk_cwnd_full(struct sock *sk){
	u32 mss_now = tcp_current_mss(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	/* is there still space? */
	return mptcp_subflow_queued(sk, tcp_tso_segs(sk, mss_now)) >= tp->snd_cwnd;
}

/* if not all the subflow cwnd is fully used, or there is only one subflow return false */
bool all_cwnd_full_check(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct mptcp_tcp_sock *mptcp;

	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);
		if (!mptcp_is_def_unavailable(sk))
			continue;
		if (!subsk_cwnd_full(sk))
			return false;
	}

	return true;
}

// check if overlap
bool overlap_check(struct sock *meta_sk, struct sk_buff *skb )
//bool overlap_check(struct sock *meta_sk,
					   //struct sk_buff *skb ,bool throughput_flag)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct mptcp_tcp_sock *mptcp;
	struct tcp_sock *best_tp, *second_tp;
	u32 plusdelta_t;
	//u32 min_transfer_time = 0xffffffff;
	u32 transfer_time = 0;
	struct sock *best_sk, *second_sk;

	best_sk = get_fastest_subflow(meta_sk, skb);//zy
	if(!best_sk)
		return false;
	second_sk = get_second_subflow(meta_sk, skb);
	if(!second_sk)
		return false;
	plusdelta_t=get_transfer_time(best_sk, skb, true);
	mptcp_debug(KERN_DEBUG "zy:[plusdelta_t,%u,us]\n",plusdelta_t >> 3);
	//if(throughput_flag)
		//return false;
	if(get_transfer_time(best_sk, skb, true) > get_transfer_time(second_sk, skb, false))
		return true;

}

/* We just look for any subflow that is available */
static struct sock *ols_get_available_subflow(struct sock *meta_sk,
					     struct sk_buff *skb,
					     bool zero_wnd_test)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk = NULL, *bestsk = NULL, *backupsk = NULL;
	struct mptcp_tcp_sock *mptcp;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sub(mpcb, mptcp) {
			sk = mptcp_to_sock(mptcp);
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_rr_is_available(sk, skb, zero_wnd_test, true))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sub(mpcb, mptcp) {
		struct tcp_sock *tp;

		sk = mptcp_to_sock(mptcp);
		tp = tcp_sk(sk);

		//if (!mptcp_rr_is_available(sk, skb, zero_wnd_test, true))
		if (!mptcp_rr_is_available(sk, skb, zero_wnd_test, false))//ytxing: we dont need cwnd test
			continue;

		if (mptcp_rr_dont_reinject_skb(tp, skb)) {
			backupsk = sk;
			continue;
		}

		bestsk = sk;
	}

	if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}

	return sk;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_ols_next_segment(const struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb)
		*reinject = 1;
	else
		skb = tcp_send_head(meta_sk);
	return skb;
}

static struct sk_buff *mptcp_ols_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
	mptcp_debug(KERN_DEBUG "***********************mptcp_ols_next_segment**************************\n");

	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct mptcp_tcp_sock *mptcp;
	struct sk_buff *skb = __mptcp_ols_next_segment(meta_sk, reinject);
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sock *best_sk = NULL, *second_sk = NULL;
	struct tcp_sock *previous_tp, *best_tp, *second_tp;
	bool overlap_flag = 0;
	struct olssched_priv *ols_p;
	struct sk_buff *redundant_skb;
	u32 in_flight, space, second_need_rate;
	bool cwnd_full_flag, redundant_flag;
	bool add_delta = 0;//意思就直接算transfer time，不加偏移量
	/* As we set it, we have to reset it as well. */
	*limit = 0;

	cwnd_full_flag = all_cwnd_full_check(meta_sk);
	if(cwnd_full_flag){
		mptcp_debug(KERN_DEBUG "all subflow cwnd full\n");
		return NULL;
	}

	if (!skb){
		return NULL;
	}

	if (*reinject) {
		*subsk = get_fastest_subflow(meta_sk, skb, false); /* ytxing: 应该选最短传输时间的流 */
		if (!*subsk)
			return NULL;

		return skb;
	}


	/* ytxing: now we try to find a redundant packet,
	 * if previous_tp is not NULL
	 */
	struct olssched_cb *ols_cb = olssched_get_cb(meta_tp);
	previous_tp = ols_cb->previous_tp;
	
	if(!previous_tp){
		/* ytxing: that means we just send a new packet
		 * the current skb will do, we find the best_tp with shortest transfer time
		 */
		 
		//mptcp_debug(KERN_DEBUG "ytxing: !previous_tp, just send a new packet\n");
		
		best_sk = get_fastest_subflow(meta_sk, skb);//TODO shan qu add_delta
		
		if(unlikely(!best_sk)){
			mptcp_debug(KERN_DEBUG "Nothing new to send, because no best_sk, strange\n");
			return NULL;
		}

		//if (!mptcp_rr_is_available(choose_sk, skb, false, true))
		if (!mptcp_rr_is_available(best_sk, skb, false, false)){//ytxing: no congestion window test
			mptcp_debug(KERN_DEBUG "Nothing to send, best_sk%u is not allowed to send skb%u\n", best_sk, TCP_SKB_CB(skb)->end_seq);
			return NULL;
		}
		best_tp = tcp_sk(best_sk);
		ols_p = olssched_get_priv(best_tp);
		*subsk = best_sk;

		overlap_flag = overlap_check(meta_sk, skb);
	 	if(overlap_flag && USE_OVERLAP){
			/* ytxing: we want to send a new packet
			 * we need redundant packet
			 * set cb and priv
			 */
			ols_cb->previous_tp = best_tp;
			ols_p->skb = skb;
			ols_p->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			mptcp_debug(KERN_DEBUG "ytxing: we need redundant packet, cb and priv are set\n");
		}
		ols_check_quota(meta_sk, best_sk, 1);
		mptcp_debug(KERN_DEBUG "[best_sk,%u,]sends new [skb,%u,]\n", best_sk, TCP_SKB_CB(skb)->end_seq);
		return skb;
	}
	
	/* ytxing: now previous_tp shows we now want to send a redundant packet 
	 * that stores in priv of previous_tp
	 */
	//mptcp_debug(KERN_DEBUG "ytxing: previous tp, want to send a redundant packet\n");
	
	ols_p = olssched_get_priv(previous_tp);
	olssched_correct_skb_pointers(meta_sk, ols_p);
	redundant_skb = ols_p->skb;

	/* ytxing: if redundant packet is sent successfully, we reset cb and priv, 
	 * if redundant packet is not sent successfully, we also reset cb and priv for simplicity.
	 *
	 * Reset cb and priv!
	 */
	
	 if(redundant_skb) {
		second_sk = get_second_subflow(meta_sk, redundant_skb);
		if(!second_sk) {
			mptcp_debug(KERN_DEBUG "Nothing to send, second_sk is NULL\n");
			redundant_skb = NULL;
			goto reset;
		}
		if (unlikely(!mptcp_rr_is_available(second_sk, redundant_skb, true, true))) {
			mptcp_debug(KERN_DEBUG "Nothing to send, cwnd_check [second_sk,%u is not allowed to send redundant_skb,%u]\n", second_sk, TCP_SKB_CB(redundant_skb)->end_seq);
			redundant_skb = NULL;
			goto reset;
		}
		if(!ols_check_quota(meta_sk, second_sk, 0)) {
			/* too much redundant data */
			redundant_skb = NULL;
			goto reset;
		}

		*subsk = second_sk;
		if (TCP_SKB_CB(redundant_skb)->path_mask){
			mptcp_debug(KERN_DEBUG "redundant_skb%u, *reinject = -1\n", TCP_SKB_CB(redundant_skb)->end_seq);
			*reinject = -1;//important
		}
	}
reset:
	//mptcp_debug(KERN_DEBUG "ytxing: Reset cb and priv\n");
	ols_cb->previous_tp = NULL;
	ols_p->skb = NULL;
	ols_p->skb_end_seq = 0;
	return redundant_skb;
}
	

static struct mptcp_sched_ops mptcp_sched_ols = {
	.get_subflow = ols_get_available_subflow,
	.next_segment = mptcp_ols_next_segment,
	.name = "ols",
	.owner = THIS_MODULE,
};

static int __init ols_register(void)
{
	BUILD_BUG_ON(sizeof(struct olssched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_ols))
		return -1;

	return 0;
}

static void ols_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_ols);
}

module_init(ols_register);
module_exit(ols_unregister);

MODULE_AUTHOR("Yitao Xing");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Overlapped Scheduler for MPTCP");
MODULE_VERSION("0.95.2");
