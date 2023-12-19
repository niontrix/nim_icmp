import std/[nativesockets, net, os, strformat, times]

type
  IcmpHeader* = object
    icmp_type*: uint8    ## message type
    icmp_code*: uint8      ## type sub-code
    icmp_checksum*: uint16
    icmp_seq*: uint16
    icmp_sequence*: uint16 ## sequence number of packet
    icmp_gateway*: uint32  ## gateway address
    # unused*: uint16
    icmp_mtu*: uint16      ## path

  EchoRequest* = object
    packet*: ptr IcmpHeader
    length*: int

  EchoResponse* = object
    packet: array[100, uint8]
    packet_len: int
    time: Duration


proc calculateChecksum(x: openArray[uint8]): uint16 =
  var sum: uint16 = 0

  for i in countup(0, x.len, 2):
    # Because we can have odd amount of bytes in x and we need to add up the
    # parts of x as DWORD increments we need to shift x[i] 8 bits to the left
    # before we can add x[i + 1]
    if i + 1 < x.len:
      sum += (x[i] shl 8) + x[i + 1]

  # add the carry over
  sum = (sum shr 16) + (sum and 0xffff)
  sum += (sum shr 16)

  # return the one complement of sum
  return (not sum)


proc newIcmpEchoRequest(nbytes: int, nsent: uint16): EchoRequest =
  ## Creates a new EchoRequest that includes a ICMP Echo Request Header adding
  ## the given number of bytes of data.
  let packet_len = nbytes + sizeof(IcmpHeader)
  var icp = cast[ptr IcmpHeader](alloc0(packet_len))
  icp.icmp_type = 8
  icp.icmp_seq = nsent
  icp.icmp_sequence = htons(nsent)

  # turn data structure IcmpHeader into an array of bytes
  let icpAsByteArray = cast[ptr array[sizeof(icp), uint8]](icp)[]
  icp.icmp_checksum = calculateChecksum(icpAsByteArray)

  result = EchoRequest(packet: icp, length: packet_len)


proc toIpAddress(ipOrHostname: string): IpAddress =
  if not isIpAddress(ipOrHostname):
    let host = getHostByName(ipOrHostname)
    result = parseIpAddress(host.addrList[0])
  else:
    result = parseIpAddress(ipOrHostname)


proc ping(ip: IpAddress, nbytes: int): EchoResponse =
  # make this a "static" variable inside this function
  var nsent {.global.}: uint16
  inc nsent

  let request = newIcmpEchoRequest(nbytes, nsent)
  let sockhandle = createNativeSocket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
  var sockaddress: SockAddr
  var socklen: SockLen
  toSockAddr(ip, Port(0), cast[var Sockaddr_storage](sockaddress.addr), socklen)

  let startTime = getTime()
  discard sockhandle.sendTo(request.packet, request.length, 0, sockaddress.addr, socklen)
  dealloc request.packet
  var buffer: array[100, byte]
  var recvCount: int = -1
  recvCount = sockhandle.recv(buffer.addr, 1024, 0)
  let endTime = getTime()
  defer: sockhandle.close()

  result = EchoResponse(packet: buffer, packet_len: recvCount, time: (endTime - startTime))



proc pingCLI(ipOrHostname: string, nbytes: int, ntimes: int) =
  let ipAddress = toIpAddress(ipOrHostname)
  echo(&"PING {ipOrHostname} ({ipAddress}) {nbytes}({nbytes + 4}) bytes of data.")

  for i in 0..<ntimes:
    let response = ping(ipAddress, nbytes)
    echo(&"{response.packet_len} bytes from {ipAddress}: icmp_seq=")
    sleep(1000)
