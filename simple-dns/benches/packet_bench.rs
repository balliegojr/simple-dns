use criterion::{black_box, criterion_group, criterion_main, Criterion};
use simple_dns::{Name, Packet, PacketBuf, PacketHeader, Question, QCLASS, QTYPE};

const DOMAINS: [&str; 4] = [
    "domain.local",
    "sub.domain.local",
    "another.domain.local",
    "sub.another.domain.local",
];
fn packet_questions() -> Vec<u8> {
    let mut query = Packet::new_query(1, false);

    for domain in DOMAINS {
        query.questions.push(Question::new(
            Name::new(domain).unwrap(),
            QTYPE::TXT,
            QCLASS::IN,
            false,
        ));
    }

    query.build_bytes_vec().unwrap()
}
fn packet_questions_compressed() -> Vec<u8> {
    let mut query = Packet::new_query(1, false);

    for domain in DOMAINS {
        query.questions.push(Question::new(
            Name::new(domain).unwrap(),
            QTYPE::TXT,
            QCLASS::IN,
            false,
        ));
    }

    query.build_bytes_vec_compressed().unwrap()
}

fn packetbuf_questions() -> Vec<u8> {
    let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
    for domain in DOMAINS {
        let question = Question::new(Name::new(domain).unwrap(), QTYPE::TXT, QCLASS::IN, false);
        buf_packet.add_question(&question).unwrap();
    }

    buf_packet.to_vec()
}

fn packetbuf_questions_compressed() -> Vec<u8> {
    let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), true);
    for domain in DOMAINS {
        let question = Question::new(Name::new(domain).unwrap(), QTYPE::TXT, QCLASS::IN, false);
        buf_packet.add_question(&question).unwrap();
    }

    buf_packet.to_vec()
}

fn packet_parse() {
    let bytes = b"\x00\x03\x81\x80\x00\x01\x00\x0b\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\
        \x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x23\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\
        \x00\x04\x4a\x7d\xec\x25\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x27\xc0\x0c\x00\x01\x00\x01\x00\x00\
        \x00\x04\x00\x04\x4a\x7d\xec\x20\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x28\xc0\x0c\x00\x01\x00\x01\
        \x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x21\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x29\xc0\x0c\x00\x01\
        \x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x22\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x24\xc0\x0c\
        \x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x2e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x26";

    Packet::parse(bytes).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("packet_questions", |b| b.iter(packet_questions));
    c.bench_function("packetbuf_questions", |b| b.iter(packetbuf_questions));
    c.bench_function("packet_questions_compressed", |b| {
        b.iter(packet_questions_compressed)
    });
    c.bench_function("packetbuf_questions_compressed", |b| {
        b.iter(packetbuf_questions_compressed)
    });
    c.bench_function("packet_parse", |b| b.iter(packet_parse));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
