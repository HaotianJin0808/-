package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
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

func main() {
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
	for packet := range packetSource.Packets() {
		// Process packet here
		num++
		fmt.Println("Frame ", num)
		//linkLayer
		fmt.Println(packet.LinkLayer().LayerType())
		fmt.Println(packet.LinkLayer().LayerContents())
		linkLayerContentsStr := hex.EncodeToString(packet.LinkLayer().LayerContents())
		fmt.Println(linkLayerContentsStr)

		fmt.Println("Destination:", linkLayerContentsStr[0:12])
		fmt.Println("Source:", linkLayerContentsStr[12:24])
		fmt.Println("Type:", linkLayerContentsStr[24:28])

		//NetworkLayer
		fmt.Println(packet.NetworkLayer().LayerType())
		fmt.Println(packet.NetworkLayer().LayerContents())
		networkLayerContentsStr := hex.EncodeToString(packet.NetworkLayer().LayerContents())
		var curNetworkContent networkIPv4Content
		networkLayerAnalyse(networkLayerContentsStr, &curNetworkContent)

		fmt.Println(networkLayerContentsStr)
		//fmt.Println("Protocol Version:", curNetworkContent.ProtocolVersion)
		//fmt.Println("Header Length:", curNetworkContent.HeaderLength)
		//fmt.Println("Total Length:", curNetworkContent.TotalLength)
		fmt.Printf("网络层报文=%+v\n", curNetworkContent)

		//TransportLayer
		//fmt.Println(packet.TransportLayer().LayerType())
		//fmt.Println(packet.TransportLayer().LayerContents())

		//fmt.Println(packet.NetworkLayer().LayerPayload())
		//fmt.Println(packet.NetworkLayer())
	}

	//router := gin.Default()
	//router.GET("/", func(c *gin.Context) {
	//	for packet := range packetSource.Packets() {
	//		c.String(200, packet.String())
	//		//c.String(200, string(packet.Layer(layers.LayerTypeIPv4).LayerContents()))
	//	}
	//
	//})
	//router.Run(":8080")
}
func networkLayerAnalyse(networkLayerContentsStr string, c *networkIPv4Content) {
	c.ProtocolVersion, _ = strconv.ParseUint(string(networkLayerContentsStr[0]), 16, 0)
	c.HeaderLength, _ = strconv.ParseUint(string(networkLayerContentsStr[1]), 16, 0)
	c.TotalLength, _ = strconv.ParseUint(networkLayerContentsStr[4:8], 16, 0)
	c.Identification, _ = strconv.ParseUint(networkLayerContentsStr[8:12], 16, 0)
	switch string(networkLayerContentsStr[12]) {
	case "4":
		c.Flags = "Don‘t Fragment"
	case "2":
		c.Flags = "More Fragments"
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
	default:
		c.Protocol = "不常见，待补充"
	}
	c.HeaderCheckSum, _ = strconv.ParseUint(string(networkLayerContentsStr[20:24]), 16, 0)
	c.SourceAddress = networkLayerContentsStr[24:32]
	c.DestinationAddress = networkLayerContentsStr[32:40]
}
