var crc32c_map = {};
var calculate_crc32c_ptr = 0x797AD4;


function setup_recv() {
	recv("packetName", function onMessage(data) {
		var crc32c = "0x" + data["packetId"].toString(16);
		var packetName = crc32c_map[crc32c];

		if (packetName != undefined) {
			send(
				{
					type: "packetName",
					packetName: packetName,
				}
			)
		}

		setup_recv();
	})
}


Java.perform(function () {
	var ArcaneLegends = Java.use("sts.al.ArcaneLegends");

	ArcaneLegends.onCreate.implementation = function (bundle) {
		this.onCreate(bundle);

		var lib_base = Process.findModuleByName("libarcanelegends.so").base;

		Interceptor.attach(ptr(lib_base.add(calculate_crc32c_ptr + 1)), {
			onEnter: function (args) {
				try {
					this.data = Memory.readUtf8String(args[0])
				}
				catch (e) {
					this.data = undefined;
				}
			},
			onLeave: function (retval) {
				if (this.data != undefined) {
					if (crc32c_map[retval] == undefined) {
						crc32c_map[retval] = this.data
					}
				}
			}
		})

		setup_recv();
	}
})
