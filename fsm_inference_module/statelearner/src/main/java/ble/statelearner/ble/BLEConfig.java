package ble.statelearner.ble;

/*
 *  Copyright (c) 2021 Imtiaz Karim
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


import ble.statelearner.LearningConfig;

import java.io.IOException;

public class BLEConfig extends LearningConfig {
	public String state_machine;
	public String ll_alphabet;
	public String smp_alphabet;
	public String recon_alphabet;
	public String alphabet;
	public String hostname;
	public String device_controller_ip_address;
	public String ble_controller_ip_address;
	public int device_controller_port;
	public int ble_controller_port;

	public boolean combine_query;
	public String delimiter_input;
	public String delimiter_output;

	public String device_adv_name;
	public String device_addr_update_needed;

	public BLEConfig(String filename) throws IOException {
		super(filename);
	}

	public BLEConfig(LearningConfig config) {
		super(config);
	}

	@Override
	public void loadProperties() {
		super.loadProperties();

		if(properties.getProperty("ll_alphabet") != null)
			ll_alphabet = properties.getProperty("ll_alphabet");

		if(properties.getProperty("smp_alphabet") != null)
			smp_alphabet = properties.getProperty("smp_alphabet");

		if(properties.getProperty("recon_alphabet") != null)
			recon_alphabet = properties.getProperty("recon_alphabet");

		if(properties.getProperty("state_machine") != null)
			state_machine = properties.getProperty("state_machine");
			if (state_machine.equalsIgnoreCase("ll")){
				alphabet = ll_alphabet;
			}
			else if (state_machine.equalsIgnoreCase("smp")){
				alphabet = smp_alphabet;
			}
			else if (state_machine.equalsIgnoreCase("recon")){
				alphabet = recon_alphabet;
			}
			else{
				alphabet = "";
			}

		if(properties.getProperty("hostname") != null)
			hostname = properties.getProperty("hostname");

		if(properties.getProperty("device_controller_ip_address") != null)
			device_controller_ip_address = properties.getProperty("device_controller_ip_address");

		if(properties.getProperty("device_controller_ip_address") != null)
			device_controller_ip_address = properties.getProperty("device_controller_ip_address");

		if(properties.getProperty("ble_controller_ip_address") != null)
			ble_controller_ip_address = properties.getProperty("ble_controller_ip_address");

		if(properties.getProperty("ble_controller_port") != null)
			ble_controller_port = Integer.parseInt(properties.getProperty("ble_controller_port"));

		if(properties.getProperty("device_controller_port") != null)
			device_controller_port = Integer.parseInt(properties.getProperty("device_controller_port"));

		if(properties.getProperty("combine_query") != null)
			combine_query = Boolean.parseBoolean(properties.getProperty("combine_query"));
		else
			combine_query = false;

		if(properties.getProperty("delimiter_input") != null)
			delimiter_input = properties.getProperty("delimiter_input");
		else
			delimiter_input = ";";

		if(properties.getProperty("delimiter_output") != null)
			delimiter_output = properties.getProperty("delimiter_output");
		else
			delimiter_output = ";";

		if(properties.getProperty("device_adv_name")!= null)
			device_adv_name = properties.getProperty("device_adv_name");
		else
			device_adv_name = "UNK";

		if(properties.getProperty("device_addr_update_needed")!= null)
			device_addr_update_needed = properties.getProperty("device_addr_update_needed");
		else
			device_addr_update_needed = "always";
	}

	public boolean getCombineQuery() {
		return combine_query;
	}
}