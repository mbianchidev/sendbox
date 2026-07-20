//! Linux egress enforcement layer.
//!
//! Everything in this module is compiled only on `target_os = "linux"`; it is
//! the sole place that performs privileged kernel operations. It owns:
//!
//! * a stable **cgroup v2 hierarchy** ([`cgroup`]) that gives the agent and the
//!   broker separate, kernel-stable identities that no other process can
//!   assume (unlike a shared UID);
//! * **`SO_MARK` socket helpers** ([`mark`]) so the broker's external sockets
//!   carry a fixed mark in addition to their cgroup identity;
//! * **nftables rendering and atomic application** ([`nft`]) that keys egress
//!   permission on `socket cgroupv2` identity plus `meta mark`, never
//!   `meta cgroup` (which is cgroup v1 `net_cls`);
//! * **preflight** ([`preflight`]) for cgroup v2, `nft socket cgroupv2`
//!   support, `CAP_NET_ADMIN`, and `SO_MARK` settability;
//! * a **supervisor** ([`supervisor`]) whose armed guard enforces the safe
//!   setup ordering (create cgroups → validate + apply nft → verify → only then
//!   allow the agent to start) and never fails open.

pub mod cgroup;
pub mod mark;
pub mod nft;
pub mod preflight;
pub mod supervisor;
