use minip2p::{Endpoint, EndpointWaitOutcome, PeerAddr, WaitDeadline};

fn main() -> Result<(), minip2p::Error> {
    let mut node = Endpoint::builder()
        .agent_version("minip2p-hello/listener")
        .listen_default()?
        .bind()?;

    println!("peer={}", node.peer_id());
    for address in node.listen_all()? {
        println!("listen={}", local_dialable(&address));
    }

    loop {
        if let EndpointWaitOutcome::Event(event) = node.wait(WaitDeadline::NEVER)? {
            println!("{event:?}");
        }
    }
}

fn local_dialable(address: &PeerAddr) -> String {
    address
        .to_string()
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
        .replace("/ip6/::/", "/ip6/::1/")
}
