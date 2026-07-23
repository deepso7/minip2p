use minip2p::{Deadline, Endpoint, PeerAddr};

fn main() -> Result<(), minip2p::Error> {
    let mut node = Endpoint::builder()
        .agent_version("minip2p-hello/listener")
        .bind_quic_dual_stack()?;

    println!("peer={}", node.peer_id());
    for address in node.listen_all()? {
        println!("listen={}", local_dialable(&address));
    }

    while let Some(event) = node.next_event(Deadline::NEVER)? {
        println!("{event:?}");
    }

    Ok(())
}

fn local_dialable(address: &PeerAddr) -> String {
    address
        .to_string()
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
        .replace("/ip6/::/", "/ip6/::1/")
}
