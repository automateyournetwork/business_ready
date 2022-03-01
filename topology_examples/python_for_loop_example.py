import businessready

device01_info = ["dist-rtr01", "cisco", "cisco", "10.10.20.175"]
device02_info = ["dist-rtr02", "cisco", "cisco", "10.10.20.176"]

device_list = [device01_info, device02_info]

for device in device_list:
    businessready.NXOS_learn_all(*device)