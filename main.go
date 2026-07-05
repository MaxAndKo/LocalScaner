package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"syscall"
	"unsafe"
)

var (
	iphlpapi   = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = iphlpapi.NewProc("SendARP")
)

// localSubnet возвращает базовый IP (первые 3 октета) локальной сети /24
// и локальный IPv4-адрес машины.
func localSubnet() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("не удалось определить локальный IPv4-адрес")
}

// arpRequest отправляет ARP-запрос к указанному IP через SendARP.
// Возвращает MAC-адрес и true, если хост ответил.
func arpRequest(ip net.IP) (string, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}

	// SendARP принимает IP в виде ULONG в сетевом порядке байтов.
	destIP := binary.LittleEndian.Uint32(ip4)

	var mac [8]byte
	macLen := uint32(len(mac))

	ret, _, _ := procSendARP.Call(
		uintptr(destIP),
		0, // SrcIP = 0 — система выберет интерфейс автоматически
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)

	// NO_ERROR (0) означает, что ARP-ответ получен.
	if ret != 0 || macLen == 0 {
		return "", false
	}

	// Нулевой MAC считаем недействительным ответом.
	var zero bool = true
	for i := uint32(0); i < macLen; i++ {
		if mac[i] != 0 {
			zero = false
			break
		}
	}
	if zero {
		return "", false
	}

	parts := make([]string, macLen)
	for i := uint32(0); i < macLen; i++ {
		parts[i] = fmt.Sprintf("%02x", mac[i])
	}
	return joinMAC(parts), true
}

func joinMAC(parts []string) string {
	res := ""
	for i, p := range parts {
		if i > 0 {
			res += ":"
		}
		res += p
	}
	return res
}

// scan сканирует всю подсеть /24 через ARP и возвращает карту IP -> MAC отвечающих устройств.
func scan(base net.IP) map[string]string {
	result := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Ограничиваем количество одновременных ARP-запросов.
	sem := make(chan struct{}, 64)

	for i := 1; i <= 254; i++ {
		ipStr := fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], i)
		ip := net.ParseIP(ipStr)
		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string, ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			if mac, ok := arpRequest(ip); ok {
				mu.Lock()
				result[ipStr] = mac
				mu.Unlock()
			}
		}(ipStr, ip)
	}

	wg.Wait()
	return result
}

// sortedIPs возвращает отсортированный список IP из карты.
func sortedIPs(set map[string]string) []string {
	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIP(ips[i], ips[j])
	})
	return ips
}

func compareIP(a, b string) bool {
	ipA := net.ParseIP(a).To4()
	ipB := net.ParseIP(b).To4()
	if ipA == nil || ipB == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ipA[i] != ipB[i] {
			return ipA[i] < ipB[i]
		}
	}
	return false
}

func main() {
	base, err := localSubnet()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}

	fmt.Printf("Локальная сеть: %d.%d.%d.0/24\n", base[0], base[1], base[2])

	fmt.Println("Первое ARP-сканирование...")
	first := scan(base)
	fmt.Printf("Найдено устройств при первом сканировании: %d\n", len(first))
	for _, ip := range sortedIPs(first) {
		fmt.Printf("   %-15s  %s\n", ip, first[ip])
	}

	fmt.Print("\nНажмите Enter для второго сканирования...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	fmt.Println("Второе ARP-сканирование...")
	second := scan(base)
	fmt.Printf("Найдено устройств при втором сканировании: %d\n", len(second))

	// Определяем новые устройства: есть во втором, но не было в первом.
	newDevices := make(map[string]string)
	for ip, mac := range second {
		if _, ok := first[ip]; !ok {
			newDevices[ip] = mac
		}
	}

	fmt.Println("\nНовые устройства (отсутствовали при 1-м, появились при 2-м сканировании):")
	if len(newDevices) == 0 {
		fmt.Println("  Новых устройств не обнаружено.")
	} else {
		for _, ip := range sortedIPs(newDevices) {
			fmt.Printf("   %-15s  %s\n", ip, newDevices[ip])
		}
	}

	fmt.Print("\nНажмите Enter для выхода...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
