import struct
import socket


class DataParser:
    def __init__(self):
        pass

    @staticmethod
    def parse_header(raw_data):
        """
        parse the first part of the received packet
        """
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        # dest_mac = format_mac_address(dest)
        # src_mac = format_mac_address(src)
        proto = socket.htons(prototype)
        data = raw_data[14:]
        return {
            "dest_mac": dest,
            "src_mac": src,
            "protocol": proto,
            "data": data
        }

    @staticmethod
    def head_ipv4(raw_data):
        """
        parse an ipv4 header
        """
        header_version_len = raw_data[0]
        version = header_version_len >> 4
        header_len = (header_version_len & 15) * 4

        # B - unsigned char (1)
        # x - pad byte
        # s - char array
        ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        data = raw_data[header_len:]
        # return header_version_len, version, header_len, ttl, protocol, src, target, data
        return {
            "header_version_len": header_version_len,
            "version": version,
            "len": header_len,
            "ttl": ttl,
            "protocol": protocol,
            "src": src,
            "target": target,
            "data": data
        }

    @staticmethod
    def head_tcp(raw_data):
        # H - unsigned short (2)
        # L - unsigned long (4)
        src_port, dest_port, sequence, ack, offset_flags = struct.unpack('! H H L L H', raw_data[:14])
        offset = (offset_flags >> 12) * 4
        # separate flags from offset
        f_urg = (offset_flags & 32) >> 5
        f_ack = (offset_flags & 16) >> 4
        f_psh = (offset_flags & 8) >> 3
        f_rst = (offset_flags & 4) >> 2
        f_syn = (offset_flags & 2) >> 1
        f_fin = offset_flags & 1
        data = raw_data[offset:]
        return {
            "src_port": src_port,
            "dest_port": dest_port,
            "sequence": sequence,
            "ack": ack,
            "f_urg": f_urg,
            "f_ack": f_ack,
            "f_psh": f_psh,
            "f_rst": f_rst,
            "f_syn": f_syn,
            "f_fin": f_fin,
            "data": data
        }

    @staticmethod
    def head_http(raw_data):
        try:
            data = raw_data.decode('utf-8')
        except UnicodeDecodeError:
            data = raw_data
        return data

    @staticmethod
    def head_icmp(raw_data):
        _type, _code, _checksum = struct.unpack('! B B H', raw_data[:4])
        data = raw_data[4:]
        return {
            "type": _type,
            "code": _code,
            "checksum": _checksum,
            "data": data
        }

    @staticmethod
    def head_udp(raw_data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
        data = raw_data[8:]
        return {
            "src_port": src_port,
            "dest_port": dest_port,
            "size": size,
            "data": data
        }
