try:
    import dns.zone
    import dns.name
    import dns.rdatatype
    import dns.zonefile
    import os
except ImportError:
    raise SystemExit("Please install dnspython")

base_name = dns.name.from_text("sample.")

def convert_zonefile(origin, root_dest):
    zone_file = open(origin, "r")
    zone = dns.zone.from_file(zone_file, base_name)

    os.makedirs(root_dest, exist_ok=True) 

    for (rname, rset) in zone.iterate_rdatasets():
        rdtype = dns.rdatatype.to_text(rset.rdtype)
        name = base_name if str(rname) == "@" else f"{base_name}{rname}"
        dest_file_name = f"{root_dest}/{rdtype}.{name}"
        dest_file = open(dest_file_name, "wb")
        rset.to_wire(rname, dest_file, origin=base_name)

def convert_rdata(origin, dest):
    input = open(origin, "r").read()
    try:
        rset = dns.zonefile.read_rrsets(input[2:], base_name, 60)[0]
        dest_file = open(dest, "wb")
        rset.to_wire(dest_file, origin=base_name )
    except Exception as err:
        print(err)



for file in os.listdir("./zonefiles"):
    convert_zonefile(f"./zonefiles/{file}", f"./simple-dns/samples/zonefile")

# for file in os.listdir("../bind9/fuzz/dns_rdata_fromtext.in"):
#     convert_rdata(f"../bind9/fuzz/dns_rdata_fromtext.in/{file}", f"./simple-dns/samples/rdata/{file}")

