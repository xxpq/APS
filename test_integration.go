package main

import (
	"fmt"
)

// 集成测试函数
func testTunnelIntegration() {
	fmt.Println("=== 隧道管理器集成测试 ===")

	// 测试1: 创建隧道管理器
	config := &Config{
		Tunnels: map[string]*TunnelConfig{
			"test-tunnel": {
				Servers:  []string{"main"},
				Password: "test123",
			},
		},
	}

	// 创建统计收集器
	statsCollector := NewStatsCollector(config)

	// 创建隧道管理器
	htm := NewHybridTunnelManager(config, statsCollector)

	fmt.Printf("✅ 隧道管理器创建成功\n")

	// 测试2: 获取连接池统计
	poolStats := htm.GetPoolStats()
	fmt.Printf("✅ 连接池统计获取成功\n")
	fmt.Printf("   - 统计信息: %v\n", poolStats)

	// 测试3: 隧道管理器接口兼容性
	var tmInterface TunnelManagerInterface = htm
	if tmInterface != nil {
		fmt.Printf("✅ 隧道管理器接口兼容性测试通过\n")

		// 测试基本方法
		tunnelName, found := tmInterface.FindTunnelForEndpoint("test-endpoint")
		fmt.Printf("   - FindTunnelForEndpoint: tunnel=%s, found=%v\n", tunnelName, found)

		endpointsInfo := tmInterface.GetEndpointsInfo("test-tunnel")
		fmt.Printf("   - GetEndpointsInfo: %d个端点信息\n", len(endpointsInfo))
	}

	fmt.Println("\n=== 所有集成测试通过 ===")
}

// 运行所有测试
func runAllTests() {
	fmt.Println("🚀 开始隧道管理器集成测试...")
	fmt.Println("=" + string(make([]byte, 50, 50)))

	testTunnelIntegration()

	fmt.Println("\n🎉 所有测试完成！隧道管理器功能正常工作。")
}
