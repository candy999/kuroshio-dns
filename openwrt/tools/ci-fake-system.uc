// CI：Docker 容器裡沒有 procd，補一個最小的 ubus「system」物件（LuCI 頁首要讀 board / info）
'use strict';
import * as ubus from 'ubus';
import * as uloop from 'uloop';

uloop.init();
const conn = ubus.connect();
conn.publish('system', {
	board: {
		call: () => ({
			kernel: '6.6.0', hostname: 'OpenWrt', system: 'CI', model: 'Docker', board_name: 'ci', rootfs_type: 'overlay',
			release: { distribution: 'OpenWrt', version: 'ci', revision: 'ci', target: 'x86/64', description: 'OpenWrt CI' }
		})
	},
	info: {
		call: () => ({
			localtime: time(), uptime: 60, load: [0, 0, 0],
			memory: { total: 2147483648, free: 1073741824, shared: 0, buffered: 0, available: 1073741824, cached: 0 },
			swap: { total: 0, free: 0 }
		})
	}
});
uloop.run();
