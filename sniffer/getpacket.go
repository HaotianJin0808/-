package main

import (
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net/http"
	"strconv"
	"time"
)

var (
	device       string = "\\Device\\NPF_{E2400578-5DB9-43A8-91CE-F1506B976E2F}"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
)

type totalContent struct {
	FrameTime              string
	FrameNum               int
	LinkLayerContent       linkLayerContent
	NetworkProtocol        string //"ipv4";"ipv6"
	NetworkIPv4Content     networkIPv4Content
	NetworkIPv6Content     networkIPv6Content
	TransportProtocol      string //"TCP";"UDP"
	TransportUDPContent    transportUDPContent
	TransportTCPContent    transportTCPContent
	ApplicationProtocol    string //"HTTP";"DNS"
	ApplicationHTTPContent applicationHTTPContent
	ApplicationDNSContent  applicationDNSContent
	SourceAddress          string
	DestinationAddress     string
	Protocol               string
	ContentsStr            string
}
type networkIPv4Content struct {
	ProtocolVersion    uint64
	HeaderLength       uint64
	TotalLength        uint64
	Identification     uint64
	Flags              string
	FragmentOffset     uint64
	TimeToLive         uint64
	Protocol           string
	HeaderCheckSum     uint64
	SourceAddress      string
	DestinationAddress string
}
type networkIPv6Content struct {
	ProtocolVersion    uint64
	TrafficClass       string
	FlowLabel          string
	PayloadLength      uint64
	NextHeader         string
	HopLimit           uint64
	SourceAddress      string
	DestinationAddress string
}
type linkLayerContent struct {
	Destination string
	Source      string
	Type        string
}
type transportTCPContent struct {
	SourcePort      uint64
	DestinationPort uint64
	SeqNumber       uint64
	AckNumber       uint64
	HeaderLength    uint64
	Flags           string
	Window          uint64
	CheckSum        string
	UrgentPointer   uint64
}

type transportUDPContent struct {
	SourcePort      uint64
	DestinationPort uint64
	Length          uint64
	CheckSum        string
}

type applicationDNSContent struct {
	TransactionID string
	Flags         string
	Questions     uint64
	AnswerRRs     uint64
	AuthorityRRs  uint64
	AdditionalRRs uint64
}
type applicationHTTPContent struct {
	content string
}

var frameContent []totalContent
var totalLinkLayerContent []linkLayerContent
var totalNetworkIPv4Content []networkIPv4Content
var totalNetworkIPv6Content []networkIPv6Content
var totalTransportTCPContent []transportTCPContent
var totalTransportUDPContent []transportUDPContent
var totalApplicationDNSContent []applicationDNSContent
var totalApplicationHTTPContent []applicationHTTPContent

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("template/*")
	router.GET("/index", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"msg": "加载index页面",
		})
	})
	// 打开某一网络设备

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Name:", device)
	defer handle.Close()
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//fmt.Println("packetSource:", packetSource)
	num := 0

	router.POST("/sniffer", func(c *gin.Context) {
		protocol := c.PostForm("protocol")
		startTime := time.Now() //
		for packet := range packetSource.Packets() {
			curTime := time.Now()
			var curFrameContent totalContent
			curFrameContent.FrameTime = curTime.Sub(startTime).String()
			fmt.Println("帧时间：", curFrameContent.FrameTime)
			// Process packet here
			num++
			fmt.Println("Frame ", num)
			//curNum := "\n" + "Frame" + strconv.Itoa(num) + "\n"
			//c.String(200, curNum)

			//linkLayer
			//fmt.Println(packet.LinkLayer().LayerType())
			//fmt.Println(packet.LinkLayer().LayerContents())
			linkLayerContentsStr := hex.EncodeToString(packet.LinkLayer().LayerContents())
			curFrameContent.ContentsStr = linkLayerContentsStr
			//fmt.Println(linkLayerContentsStr)
			var curLinkLayerContent linkLayerContent
			linkLayerAnalyse(linkLayerContentsStr, &curLinkLayerContent)
			fmt.Printf("链路层报文=%+v\n", curLinkLayerContent)
			totalLinkLayerContent = append(totalLinkLayerContent, curLinkLayerContent)
			//c.String(200, "链路层报文")
			//c.JSON(200, curLinkLayerContent)
			//c.String(200, "\n")
			curFrameContent.LinkLayerContent = curLinkLayerContent
			curFrameContent.FrameNum = num
			//
			//fmt.Println("Destination:", linkLayerContentsStr[0:12])
			//fmt.Println("Source:", linkLayerContentsStr[12:24])
			//fmt.Println("Type:", linkLayerContentsStr[24:28])

			//NetworkLayer
			//fmt.Println(packet.NetworkLayer().LayerType().String())
			if packet.NetworkLayer() == nil {
				continue
			}
			fmt.Println("网络层野生报文", packet.NetworkLayer().LayerContents())
			networkLayerContentsStr := hex.EncodeToString(packet.NetworkLayer().LayerContents())
			curFrameContent.ContentsStr += networkLayerContentsStr
			//fmt.Println(networkLayerContentsStr)
			var curNetworkIPv4Content networkIPv4Content
			var curNetworkIPv6Content networkIPv6Content
			var curTransportTCPContent transportTCPContent
			var curTransportUDPContent transportUDPContent
			//c.String(200, "网络层报文")
			if "IPv4" == packet.NetworkLayer().LayerType().String() {
				networkLayerIPv4Analyse(networkLayerContentsStr, packet.NetworkLayer().LayerContents(), &curNetworkIPv4Content)
				fmt.Printf("网络层报文=%+v\n", curNetworkIPv4Content)
				totalNetworkIPv4Content = append(totalNetworkIPv4Content, curNetworkIPv4Content)
				//c.JSON(200, curNetworkIPv4Content)
				curFrameContent.NetworkIPv4Content = curNetworkIPv4Content
				curFrameContent.SourceAddress = curNetworkIPv4Content.SourceAddress
				curFrameContent.DestinationAddress = curNetworkIPv4Content.DestinationAddress
				curFrameContent.NetworkProtocol = "ipv4"
			}
			if "IPv6" == packet.NetworkLayer().LayerType().String() {
				networkLayerIPv6Analyse(networkLayerContentsStr, &curNetworkIPv6Content)
				fmt.Printf("网络层报文=%+v\n", curNetworkIPv6Content)
				//c.JSON(200, curNetworkIPv6Content)
				curFrameContent.NetworkIPv6Content = curNetworkIPv6Content
				curFrameContent.SourceAddress = curNetworkIPv6Content.SourceAddress
				curFrameContent.DestinationAddress = curNetworkIPv6Content.DestinationAddress
				curFrameContent.NetworkProtocol = "ipv6"
				//if "TCP(6)" == curNetworkIPv6Content.NextHeader { //传输层为TCP协议
				//	transportLayerContentsStr := hex.EncodeToString(packet.TransportLayer().LayerContents())
				//
				//	transportLayerTCPAnalyse(transportLayerContentsStr, &curTransportTCPContent)
				//	fmt.Printf("传输层TCP报文=%+v\n", curTransportTCPContent)
				//	totalTransportTCPContent = append(totalTransportTCPContent, curTransportTCPContent)
				//	c.JSON(200, curTransportTCPContent)
				//	if curTransportTCPContent.SourcePort == 53 || curTransportTCPContent.DestinationPort == 53 {
				//		//DNS报文
				//		applicationLayerContentStr := hex.EncodeToString(packet.ApplicationLayer().LayerContents())
				//		var curApplicationDNSContent applicationDNSContent
				//		applicationLayerDNSAnalyse(applicationLayerContentStr, &curApplicationDNSContent)
				//		fmt.Printf("应用层DNS报文=%+v\n", curApplicationDNSContent)
				//		totalApplicationDNSContent = append(totalApplicationDNSContent, curApplicationDNSContent)
				//		c.JSON(200, curApplicationDNSContent)
				//	}
				//} else if "UDP(17)" == curNetworkIPv6Content.NextHeader { //传输层为UDP协议
				//	transportLayerContentsStr := hex.EncodeToString(packet.TransportLayer().LayerContents())
				//	var curTransportUDPContent transportUDPContent
				//	transportLayerUDPAnalyse(transportLayerContentsStr, &curTransportUDPContent)
				//	fmt.Printf("传输层UDP报文=%+v\n", curTransportUDPContent)
				//	totalTransportUDPContent = append(totalTransportUDPContent, curTransportUDPContent)
				//	c.JSON(200, curTransportUDPContent)
				//	if curTransportUDPContent.SourcePort == 53 || curTransportUDPContent.DestinationPort == 53 {
				//		//DNS报文
				//		applicationLayerContentStr := hex.EncodeToString(packet.ApplicationLayer().LayerContents())
				//		var curApplicationDNSContent applicationDNSContent
				//		applicationLayerDNSAnalyse(applicationLayerContentStr, &curApplicationDNSContent)
				//		fmt.Printf("应用层DNS报文=%+v\n", curApplicationDNSContent)
				//		totalApplicationDNSContent = append(totalApplicationDNSContent, curApplicationDNSContent)
				//		c.JSON(200, curApplicationDNSContent)
				//	}
				//}
			}
			//c.String(200, "\n")
			if "TCP(6)" == curNetworkIPv4Content.Protocol || "TCP(6)" == curNetworkIPv6Content.NextHeader {
				//传输层为TCP协议
				//c.String(200, "传输层报文")
				transportLayerContentsStr := hex.EncodeToString(packet.TransportLayer().LayerContents())

				curFrameContent.ContentsStr += transportLayerContentsStr
				transportLayerTCPAnalyse(transportLayerContentsStr, &curTransportTCPContent)
				fmt.Printf("传输层TCP报文=%+v\n", curTransportTCPContent)
				totalTransportTCPContent = append(totalTransportTCPContent, curTransportTCPContent)
				//c.JSON(200, curTransportTCPContent)
				curFrameContent.TransportTCPContent = curTransportTCPContent
				curFrameContent.TransportProtocol = "TCP"
				curFrameContent.Protocol = "TCP"
				//if curTransportTCPContent.SourcePort == 53 || curTransportTCPContent.DestinationPort == 53 {
				//	//DNS报文
				//	applicationLayerContentStr := hex.EncodeToString(packet.ApplicationLayer().LayerContents())
				//	var curApplicationDNSContent applicationDNSContent
				//	applicationLayerDNSAnalyse(applicationLayerContentStr, &curApplicationDNSContent)
				//	fmt.Printf("应用层DNS报文=%+v\n", curApplicationDNSContent)
				//	totalApplicationDNSContent = append(totalApplicationDNSContent, curApplicationDNSContent)
				//	c.JSON(200, curApplicationDNSContent)
				//}
			} else if "UDP(17)" == curNetworkIPv4Content.Protocol || "UDP(17)" == curNetworkIPv6Content.NextHeader {
				//传输层为UDP协议
				//c.String(200, "传输层报文")
				transportLayerContentsStr := hex.EncodeToString(packet.TransportLayer().LayerContents())
				curFrameContent.ContentsStr += transportLayerContentsStr
				transportLayerUDPAnalyse(transportLayerContentsStr, &curTransportUDPContent)
				fmt.Printf("传输层UDP报文=%+v\n", curTransportUDPContent)
				totalTransportUDPContent = append(totalTransportUDPContent, curTransportUDPContent)
				//c.JSON(200, curTransportUDPContent)
				curFrameContent.TransportUDPContent = curTransportUDPContent
				curFrameContent.TransportProtocol = "UDP"
				curFrameContent.Protocol = "UDP"
				//if curTransportUDPContent.SourcePort == 53 || curTransportUDPContent.DestinationPort == 53 {
				//	//DNS报文
				//	applicationLayerContentStr := hex.EncodeToString(packet.ApplicationLayer().LayerContents())
				//	var curApplicationDNSContent applicationDNSContent
				//	applicationLayerDNSAnalyse(applicationLayerContentStr, &curApplicationDNSContent)
				//	fmt.Printf("应用层DNS报文=%+v\n", curApplicationDNSContent)
				//	totalApplicationDNSContent = append(totalApplicationDNSContent, curApplicationDNSContent)
				//	c.JSON(200, curApplicationDNSContent)
				//}
			}
			//c.String(200, "\n"+"总报文信息")
			//c.JSON(200, curFrameContent)

			//c.HTML(200, "packet.html", gin.H{
			//	"curFrameContent": curFrameContent,
			//})
			if packet.ApplicationLayer() == nil {
				continue
			} else {
				//fmt.Println("应用层野生报文：", packet.ApplicationLayer().LayerContents())
				if curTransportTCPContent.SourcePort == 80 || curTransportTCPContent.DestinationPort == 80 ||
					curTransportUDPContent.SourcePort == 80 || curTransportUDPContent.DestinationPort == 80 {
					applicationLayerContentStr := hex.EncodeToString(packet.ApplicationLayer().LayerContents())
					fmt.Println("HTTP报文：", applicationLayerContentStr)

					var curApplicationHTTPContent applicationHTTPContent
					applicationLayerHTTPAnalyse(applicationLayerContentStr, &curApplicationHTTPContent)
					totalApplicationHTTPContent = append(totalApplicationHTTPContent, curApplicationHTTPContent)
					curFrameContent.Protocol = "HTTP"
					curFrameContent.ApplicationProtocol = "HTTP"
					curFrameContent.ApplicationHTTPContent = curApplicationHTTPContent
				} else if curTransportTCPContent.SourcePort == 53 || curTransportTCPContent.DestinationPort == 53 ||
					curTransportUDPContent.SourcePort == 53 || curTransportUDPContent.DestinationPort == 53 {
					//DNS报文
					applicationLayerContentStr := hex.EncodeToString(packet.ApplicationLayer().LayerContents())
					fmt.Println("应用层16进制报文", applicationLayerContentStr)
					if len(applicationLayerContentStr) < 12 {
						continue
					}
					var curApplicationDNSContent applicationDNSContent
					applicationLayerDNSAnalyse(applicationLayerContentStr, &curApplicationDNSContent)
					fmt.Printf("应用层DNS报文=%+v\n", curApplicationDNSContent)
					totalApplicationDNSContent = append(totalApplicationDNSContent, curApplicationDNSContent)
					curFrameContent.Protocol = "DNS"
					curFrameContent.ApplicationProtocol = "DNS"
					curFrameContent.ApplicationDNSContent = curApplicationDNSContent
					//c.String(200, "应用层DNS报文：")
					//c.JSON(200, curApplicationDNSContent)
				}
			}

			//fmt.Println("Protocol Version:", curNetworkContent.ProtocolVersion)
			//fmt.Println("Header Length:", curNetworkContent.HeaderLength)
			//fmt.Println("Total Length:", curNetworkContent.TotalLength)

			//TransportLayer
			//fmt.Println(packet.TransportLayer().LayerType())
			//if packet.TransportLayer() == nil {
			//	fmt.Println("无传输层报文")
			//} else {
			//	fmt.Println("传输层野生报文：")
			//	//transportLayerContentsStr := hex.EncodeToString(packet.TransportLayer().LayerContents())
			//	//var curTransportTCPContent transportTCPContent
			//	//transportLayerTCPAnalyse(transportLayerContentsStr, &curTransportTCPContent)
			//	//fmt.Printf("传输层报文=%+v\n", curTransportTCPContent)
			//}

			frameContent = append(frameContent, curFrameContent)
			if "all" == protocol {
				c.HTML(200, "packet.html", gin.H{
					"curFrameContent": curFrameContent,
				})
			} else if curFrameContent.Protocol == protocol {
				c.HTML(200, "packet.html", gin.H{
					"curFrameContent": curFrameContent,
				})
			} else {
				continue
			}

		}

	})
	router.Run(":8080")
}

func linkLayerAnalyse(linkLayerContentsStr string, c *linkLayerContent) {
	c.Destination = linkLayerContentsStr[0:2] + ":" + linkLayerContentsStr[2:4] + ":" + linkLayerContentsStr[4:6] + ":" +
		linkLayerContentsStr[6:8] + ":" + linkLayerContentsStr[8:10] + ":" + linkLayerContentsStr[10:12]
	c.Source = linkLayerContentsStr[12:14] + ":" + linkLayerContentsStr[14:16] + ":" + linkLayerContentsStr[16:18] + ":" +
		linkLayerContentsStr[18:20] + ":" + linkLayerContentsStr[20:22] + ":" + linkLayerContentsStr[22:24]
	c.Type = linkLayerContentsStr[24:28]
}
func networkLayerIPv4Analyse(networkLayerContentsStr string, networkLayerContent []byte, c *networkIPv4Content) {
	c.ProtocolVersion, _ = strconv.ParseUint(string(networkLayerContentsStr[0]), 16, 0)
	c.HeaderLength, _ = strconv.ParseUint(string(networkLayerContentsStr[1]), 16, 0)
	c.TotalLength, _ = strconv.ParseUint(networkLayerContentsStr[4:8], 16, 0)
	c.Identification, _ = strconv.ParseUint(networkLayerContentsStr[8:12], 16, 0)
	switch string(networkLayerContentsStr[12]) {
	case "4":
		c.Flags = "Don‘t Fragment"
	case "2":
		c.Flags = "More Fragments"
	case "0":
		c.Flags = "Last Fragment"
	default:
		c.Flags = "我也不知道"
	}
	c.FragmentOffset, _ = strconv.ParseUint(string(networkLayerContentsStr[13:16]), 16, 0)
	c.TimeToLive, _ = strconv.ParseUint(string(networkLayerContentsStr[16:18]), 16, 0)
	switch networkLayerContentsStr[18:20] {
	case "01":
		c.Protocol = "ICMP(1)"
	case "02":
		c.Protocol = "IGMP(2)"
	case "06":
		c.Protocol = "TCP(6)"
	case "11":
		c.Protocol = "UDP(17)"
	default:
		c.Protocol = "不常见，待补充"
	}
	c.HeaderCheckSum, _ = strconv.ParseUint(string(networkLayerContentsStr[20:24]), 16, 0)
	c.SourceAddress = hexToDec(networkLayerContentsStr[24:26]) + ":" + hexToDec(networkLayerContentsStr[26:28]) +
		":" + hexToDec(networkLayerContentsStr[28:30]) + ":" + hexToDec(networkLayerContentsStr[30:32])
	c.DestinationAddress = hexToDec(networkLayerContentsStr[32:34]) + ":" + hexToDec(networkLayerContentsStr[34:36]) +
		":" + hexToDec(networkLayerContentsStr[36:38]) + ":" + hexToDec(networkLayerContentsStr[38:40])
}
func hexToDec(a string) (b string) {
	n, _ := strconv.ParseInt(a, 16, 0)
	return strconv.FormatInt(n, 10)
}
func networkLayerIPv6Analyse(networkLayerContentsStr string, c *networkIPv6Content) {
	c.ProtocolVersion, _ = strconv.ParseUint(string(networkLayerContentsStr[0]), 16, 0)
	c.TrafficClass = "0x" + networkLayerContentsStr[1:3]
	c.FlowLabel = "0x" + networkLayerContentsStr[3:8]
	c.PayloadLength, _ = strconv.ParseUint(string(networkLayerContentsStr[8:12]), 16, 0)
	switch networkLayerContentsStr[12:14] {
	case "06":
		c.NextHeader = "TCP(6)"
	case "01":
		c.NextHeader = "ICMP(1)"
	case "02":
		c.NextHeader = "IGMP(2)"
	case "03":
		c.NextHeader = "GGP(3)"
	case "04":
		c.NextHeader = "IPv4(4)"
	case "11":
		c.NextHeader = "UDP(17)"
	case "24":
		c.NextHeader = "XTP(36)"
	case "3a":
		c.NextHeader = "IPv6-ICMP (58)"
	default:
		c.NextHeader = "待补充"
	}
	c.HopLimit, _ = strconv.ParseUint(string(networkLayerContentsStr[14:16]), 16, 0)
	c.SourceAddress = networkLayerContentsStr[16:20] + ":" + networkLayerContentsStr[20:24] + ":" + networkLayerContentsStr[24:28] + ":" +
		networkLayerContentsStr[28:32] + ":" + networkLayerContentsStr[32:36] + ":" + networkLayerContentsStr[36:40] + ":" +
		networkLayerContentsStr[40:44] + ":" + networkLayerContentsStr[44:48]
	c.DestinationAddress = networkLayerContentsStr[48:52] + ":" + networkLayerContentsStr[52:56] + ":" + networkLayerContentsStr[56:60] + ":" +
		networkLayerContentsStr[60:64] + ":" + networkLayerContentsStr[64:68] + ":" + networkLayerContentsStr[68:72] + ":" +
		networkLayerContentsStr[72:76] + ":" + networkLayerContentsStr[76:80]
}
func transportLayerTCPAnalyse(transportLayerContentsStr string, c *transportTCPContent) {
	c.SourcePort, _ = strconv.ParseUint(string(transportLayerContentsStr[0:4]), 16, 0)
	c.DestinationPort, _ = strconv.ParseUint(string(transportLayerContentsStr[4:8]), 16, 0)
	c.SeqNumber, _ = strconv.ParseUint(string(transportLayerContentsStr[8:16]), 16, 0)
	c.AckNumber, _ = strconv.ParseUint(string(transportLayerContentsStr[16:24]), 16, 0)
	c.HeaderLength, _ = strconv.ParseUint(string(transportLayerContentsStr[24]), 16, 0)
	c.Flags = "0x" + transportLayerContentsStr[25:28]
	c.Window, _ = strconv.ParseUint(string(transportLayerContentsStr[28:32]), 16, 0)
	c.CheckSum = "0x" + transportLayerContentsStr[32:36]
	c.UrgentPointer, _ = strconv.ParseUint(string(transportLayerContentsStr[36:40]), 16, 0)
}
func transportLayerUDPAnalyse(transportLayerContentsStr string, c *transportUDPContent) {
	c.SourcePort, _ = strconv.ParseUint(string(transportLayerContentsStr[0:4]), 16, 0)
	c.DestinationPort, _ = strconv.ParseUint(string(transportLayerContentsStr[4:8]), 16, 0)
	c.Length, _ = strconv.ParseUint(string(transportLayerContentsStr[8:12]), 16, 0)
	c.CheckSum = "0x" + transportLayerContentsStr[12:16]
}
func applicationLayerDNSAnalyse(applicationLayerContentsStr string, c *applicationDNSContent) {
	c.TransactionID = "0x" + applicationLayerContentsStr[0:4]
	c.Flags = "0x" + applicationLayerContentsStr[4:8]
	c.Questions, _ = strconv.ParseUint(string(applicationLayerContentsStr[8:12]), 16, 0)
	c.AnswerRRs, _ = strconv.ParseUint(string(applicationLayerContentsStr[12:16]), 16, 0)
	c.AuthorityRRs, _ = strconv.ParseUint(string(applicationLayerContentsStr[16:20]), 16, 0)
	c.AdditionalRRs, _ = strconv.ParseUint(string(applicationLayerContentsStr[20:24]), 16, 0)
}
func applicationLayerHTTPAnalyse(applicationLayerContentsStr string, c *applicationHTTPContent) {
	for i := 0; i < len(applicationLayerContentsStr)-2; i = i + 2 {
		tmpHexStr := applicationLayerContentsStr[i : i+2]
		tmpDecNum, _ := strconv.ParseInt(tmpHexStr, 16, 0)
		c.content += string(tmpDecNum)
	}
}
