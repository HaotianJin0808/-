package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
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
	//for packet := range packetSource.Packets() {
	//	// Process packet here
	//	fmt.Println(packet.String())
	//}

	router := gin.Default()
	router.GET("/", func(c *gin.Context) {
		for packet := range packetSource.Packets() {
			c.String(200, packet.String())
			//c.String(200, string(packet.Layer(layers.LayerTypeIPv4).LayerContents()))
		}

	})
	router.Run(":8080")
}
