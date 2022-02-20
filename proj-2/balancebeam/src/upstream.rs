use crate::request;

use tokio::sync::RwLock;
use std::sync::Arc;
use tokio::net::TcpStream;

/// A thread-safe struct for manipulating upstream server addresses
///
/// **upstream_addr_lock** stores all available upstream server addresses;
/// **removed_upstream_addr_lock** stores all upstream server addresses that we failed to connect
#[derive(Clone)]
pub struct Upstream{
    pub upstream_addr_lock: Arc<RwLock<Vec<String>>>,
    pub removed_addr_lock: Arc<RwLock<Vec<String>>>
}

impl Upstream{
    pub fn new(upstream_addr: Vec<String>) -> Upstream{
        let upstream_addr_lock = Arc::new(RwLock::new(upstream_addr));
        let removed_addr_lock = Arc::new(RwLock::new(Vec::new()));
        return Upstream{upstream_addr_lock, removed_addr_lock};
    }

    /// Get a upstream server address via an index
    pub async fn get(&self, idx: usize) -> String{
        let addrs_res = self.upstream_addr_lock.read().await;
        return addrs_res[idx].clone();
    }

    /// Get length of available upstream server addresses
    pub async fn len(&self) -> usize{
        let addrs = self.upstream_addr_lock.read().await;
        return addrs.len();
    }

    /// Remove a server address from the upstream server list
    ///
    /// If **addr_to_remove** is in removed_addr, then it indicates that we already
    /// removed this address; otherwise, this address is still available, so we remove it
    /// from upstream_addr
    pub async fn try_remove(
        upstream_addr_lock: Arc<RwLock<Vec<String>>>,
        removed_addr_lock: Arc<RwLock<Vec<String>>>,
        addr_to_remove: &String
    ) {
        let removed_addr = removed_addr_lock.read().await;
        if removed_addr.contains(addr_to_remove) {
            // Someone already removed it
            return;
        }
        // No one has removed this address, so it's ok to remove it now
        drop(removed_addr);
        let mut upstream_addr = upstream_addr_lock.write().await;
        let mut removed_addr = removed_addr_lock.write().await;
        let addr_idx = upstream_addr.iter().position(|r| r.eq(addr_to_remove)).unwrap();
        upstream_addr.remove(addr_idx);
        removed_addr.push(addr_to_remove.clone());
        log::info!("[try_remove]: Remove {} from upstream", addr_to_remove);
    }

    /// Push a server address to the upstream server list
    ///
    /// If **addr_to_push** is not in removed_addr, then it indicates that we already
    /// pushed this address; otherwise, we should add it into our available upstreams,
    /// so we push it to upstream_addr
    pub async fn try_push(
        upstream_addr_lock: Arc<RwLock<Vec<String>>>,
        removed_addr_lock: Arc<RwLock<Vec<String>>>,
        addr_to_push: &String
    ) {
        let removed_addr = removed_addr_lock.read().await;
        if !removed_addr.contains(addr_to_push) {
            // Someone already pushed it
            return;
        }
        // No one has pushed this address, so it's ok to push it now
        drop(removed_addr);
        let mut removed_addr = removed_addr_lock.write().await;
        let mut upstream_addr = upstream_addr_lock.write().await;
        let addr_idx = removed_addr.iter().position(|r| r.eq(addr_to_push)).unwrap();
        removed_addr.remove(addr_idx);
        upstream_addr.push(addr_to_push.clone());
        log::info!("[try_push]: Push {} to upstream", addr_to_push);
    }


    /// Do active health check
    ///
    /// If a server recovers from a connection failure, add it back to the available upstream
    /// using **try_push**
    ///
    /// If a server fails a connection, add it to removed upstream using **try_remove**
    pub async fn active_health_check(
        upstream_addr_lock: Arc<RwLock<Vec<String>>>,
        removed_addr_lock: Arc<RwLock<Vec<String>>>,
        path: String,
    ) {
        // Clone these values so we can move it into the following closure, whose lifetime exceeds this method's
        let upstream_addr_lock = upstream_addr_lock.clone();
        let removed_addr_lock = removed_addr_lock.clone();
        let path = path.clone();

        tokio::spawn(async move {
            // check unavailable upstream servers, add it to available upstreams if probe returns true
            let removed_addr = removed_addr_lock.read().await;
            let mut to_push: Vec<String> = Vec::new();

            // find out servers to be pushed
            for i in 0..removed_addr.len(){
                let upstream_ip = &removed_addr[i];
                let alive = Self::probe(&path, upstream_ip).await;
                if alive {
                    log::info!("[active_health_check]: {} is now alive", upstream_ip);
                    to_push.push(upstream_ip.clone());
                }
            }
            drop(removed_addr);

            // push servers to available upstreams
            for addr in &to_push{
                Self::try_push(
                    upstream_addr_lock.clone(),
                    removed_addr_lock.clone(),
                    &addr
                ).await;
            }

            // check available upstream servers, add it to unavailable upstreams if probe returns false
            let upstream_addr = upstream_addr_lock.read().await;
            let mut to_remove: Vec<String> = Vec::new();

            // find out servers to be removed
            for i in 0..upstream_addr.len(){
                let upstream_ip = &upstream_addr[i];
                let alive = Self::probe(&path, upstream_ip).await;
                if !alive{
                    log::info!("[active_health_check]: {} is now dead", upstream_ip);
                    to_remove.push(upstream_ip.clone());
                }
            }

            // remove servers from available upstreams
            for addr in to_remove{
                Self::try_remove(
                    upstream_addr_lock.clone(),
                    removed_addr_lock.clone(),
                    &addr
                ).await;
            }
        });
    }

    /// Probe a server to see if it's alive
    ///
    /// Returns true if the server is alive, false otherwise
    pub async fn probe(path: &String, upstream_ip: &String) -> bool{
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(path)
            .header("Host", upstream_ip)
            .body(vec![0 as u8])
            .unwrap();
        let res = TcpStream::connect(&upstream_ip).await;
        let mut upstream_conn = match res{
            Ok(stream) => { stream },
            Err(err) => {
                log::error!("Failed to connect to upstream {}: {}", upstream_ip, err);
                return false;
            }
        };
        if let Err(error) = request::write_to_stream(&request, &mut upstream_conn).await {
            log::error!("Failed to send request to upstream {}: {}", upstream_ip, error);
            return false;
        }
        return true;
    }
}