package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	// 得到所有的(网络)设备
	//router := gin.Default()
	//router.LoadHTMLGlob("template/*")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// 打印设备信息
	var deviceName []string
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		deviceName = append(deviceName, device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
	//router.GET("/index", func(c *gin.Context) {
	//	c.HTML(http.StatusOK, "index.html", gin.H{
	//		"msg": "加载index页面",
	//	})
	//})
	//router.POST("/device", func(c *gin.Context) {
	//	c.HTML(200, "packet.html", gin.H{
	//		"deviceName": deviceName,
	//	})
	//})
	//router.Run(":8081")
}
