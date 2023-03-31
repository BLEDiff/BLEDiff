package ble.statelearner.ble.devices;

/*
 *  Copyright (c) 2022 Imtiaz Karim & Abdullah Al Ishtiaq
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

import ble.statelearner.ble.BLESUL;
import ble.statelearner.ble.devices.*;


public class Device_SUL_Factory{
    public static Device_SUL get_Device_SUL(String device_name, BLESUL blesul, String state_machine){
        switch (device_name){
            case "nexus6":
                return new Nexus6_SUL(blesul, state_machine);
        }
        return null;
    }

}