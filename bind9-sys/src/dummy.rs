#![allow(unused)]

pub fn wire_to_text(_data: &[u8], _class: u16, _type_: u16) -> String {
    panic!("This function is only implemented when 'check-bind9' feature is used");
}

pub fn text_to_wire(_data: &str, _class: u16, _type_: u16) -> Vec<u8> {
    panic!("This function is only implemented when 'check-bind9' feature is used");
}
