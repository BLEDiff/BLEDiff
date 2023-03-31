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

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static ble.statelearner.LogOracle.sul_post_value;
import static java.lang.Thread.sleep;


public class Nexus6_SUL extends Device_SUL{
    public Nexus6_SUL(BLESUL blesul, String state_machine) {
        super(blesul, state_machine);
    }

    private int pre_reset_counter = 0;
    private String last_pair = "";
    private int num_symbols_after_pre = 0;
    
    
    
    public void pre() {
        if(this.state_machine.equalsIgnoreCase("ll")){
            this.ll_pre();
        }
        else if(this.state_machine.equalsIgnoreCase("smp")){
            this.smp_pre();
        }
        else if(this.state_machine.equalsIgnoreCase("recon")){
            this.recon_pre();
        }
        else{
            System.out.println("State machine not recognized");
            System.exit(1);
        }
    }

    public void ll_pre() {
        if (!blesul.config.combine_query) {
            String result = new String("");
            String result_for_ble_controller = new String("");
            String result_for_device = new String("");
            boolean reset_done = false;
            System.out.println("---- Starting RESET ----");
            result_for_ble_controller = blesul.reset_ble();
            result_for_device = blesul.reset_device();
            boolean need_update = false;
            boolean update_slave_success = false;
            if(blesul.config.device_addr_update_needed.equalsIgnoreCase("test")){
                need_update = blesul.needSlaveAddressUpdate();
            }
            else if(blesul.config.device_addr_update_needed.equalsIgnoreCase("always")){
                need_update = true;
            }

            System.out.println("Slave address needs update : " + need_update);
            while (need_update && !update_slave_success) {
                update_slave_success = blesul.sendSlaveAddress();
                System.out.println("Slave address update successful : " + update_slave_success);
            }
            int counter = 0;

            result = step("scan_req");
            while(!result.equals("scan_resp")) {
                System.out.println("Didn't receive scan_resp");
                counter++;
                if (counter%5 == 0) {
                    pre();
                    num_symbols_after_pre = 0;
                }
                result = step("scan_req");
            }
            num_symbols_after_pre = 0;
            System.out.println("---- RESET DONE ----");
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public void smp_pre() {
        if (!blesul.config.combine_query) {
            String result = new String("");
            String result_for_ble_controller = new String("");
            String result_for_device = new String("");
            boolean reset_done = false;
            System.out.println("---- Starting RESET ----");
            result_for_ble_controller = blesul.reset_ble();
            result_for_device = blesul.reset_device();
            boolean need_update = false;
            boolean update_slave_success = false;
            if(blesul.config.device_addr_update_needed.equalsIgnoreCase("test")){
                need_update = blesul.needSlaveAddressUpdate();
            }
            else if(blesul.config.device_addr_update_needed.equalsIgnoreCase("always")){
                need_update = true;
            }

            System.out.println("Slave address needs update : " + need_update);
            while (need_update && !update_slave_success) {
                update_slave_success = blesul.sendSlaveAddress();
                System.out.println("Slave address update successful : " + update_slave_success);
            }


            result = step("scan_req");
            while(!result.equals("scan_resp")) {
                System.out.println("Didn't receive scan_resp");
                result = step("scan_req");
            }
            result = step("con_req");

            try {
                sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            step("feature_req");
            result = step("pri_req");
            if(!result.equals("pri_resp")) {
                pre();
            }
            num_symbols_after_pre = 0;
            System.out.println("---- RESET DONE ----");
            try {
                TimeUnit.SECONDS.sleep(5);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }
    }


    public void recon_pre() {
        if (!blesul.config.combine_query) {
            String result = new String("");
            String result_for_ble_controller = new String("");
            String result_for_device = new String("");
            boolean reset_done = false;
            System.out.println("---- Starting RESET ----");
            result_for_ble_controller = blesul.reset_ble();
            result_for_device = blesul.reset_device();
            boolean need_update = false;
            boolean update_slave_success = false;
            if(blesul.config.device_addr_update_needed.equalsIgnoreCase("test")){
                need_update = blesul.needSlaveAddressUpdate();
            }
            else if(blesul.config.device_addr_update_needed.equalsIgnoreCase("always")){
                need_update = true;
            }

            System.out.println("Slave address needs update : " + need_update);
            while (need_update && !update_slave_success) {
                update_slave_success = blesul.sendSlaveAddress();
                System.out.println("Slave address update successful : " + update_slave_success);
            }

            try {
                TimeUnit.SECONDS.sleep(0);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            step("scan_req");
            step("con_req");
            step("feature_req");
            result = step("pri_req");
            result = step("pair_req");
            result = step("key_exchange");
            result = step("sm_random_send");
            result = step("dh_check");
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            step("discon_req");
            try {
                TimeUnit.SECONDS.sleep(5);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            step("scan_req");
            step("con_req");
            step("feature_req");
            result = step("pri_req");
            if(!result.equals("pri_resp")) {
                this.pre();
            }
            try {
                TimeUnit.SECONDS.sleep(2);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("---- RESET DONE ----");
        }
    }


    public void post(){
        
    }
    public String send_scan_request() {
        String result = "";
        try {
            blesul.ble_controller_socket.setSoTimeout(5 * 1000);
            blesul.ble_controller_out.write("scan_request" + "\n");
            blesul.ble_controller_out.flush();
            result = blesul.ble_controller_in.readLine();
            if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
            }
            result = blesul.getClosests(result);
            while (result.contains("adv_ind") || result.contains("DONE") || !result.contains("scan_resp")) {
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
            }
        } catch (SocketTimeoutException e) {
            System.out.println("Timeout occured for " + "scan_request");
            return "null_action";
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    public String step(String symbol) {
        num_symbols_after_pre++;
        try {
            sleep(50); //50 milliseconds
        } catch (Exception e) {
            e.printStackTrace();
        }

        String result = "";
        String result_ble_controller = "";
        String scan_result = "";
        String result_for_device = "";

        if (symbol.startsWith("scan_req")) {
            boolean got_scan_resp = false;
            try {
                blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
                int resend_scan_req_counter = 0;
                while (!result.contains("scan_resp")) {

                    if (!result.contains("adv_ind")){
                        if (resend_scan_req_counter > 10){
                            return "null_action";
                        }
                        System.out.println("*** RESENDING scan_resp ***");
                        resend_scan_req_counter++;
                        blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                        blesul.ble_controller_out.write(symbol + "\n");
                        blesul.ble_controller_out.flush();
                    }
                    try {
                        result = blesul.ble_controller_in.readLine();
                        if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                            result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                        }
                        result = blesul.getClosests(result);

                        if (result.contains("scan_resp")){
                            System.out.println("** GOT scan_resp IN IF ***");
                            got_scan_resp = true;
                            break;
                        }
                    }
                    catch (SocketTimeoutException e){
                        result = "null_action";
                    }
                }
                while (result.contains("scan_resp") ){   // consume all scan_resps
                    System.out.println("** GOT scan_resp IN WHILE ***");
                    got_scan_resp = true;
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                }
                if(got_scan_resp){
                    result = "scan_resp";
                }
            } catch (SocketTimeoutException e) {
                if(got_scan_resp){
                    result = "scan_resp";
                }
                else{
                    System.out.println("Timeout occured for " + symbol);
                    result = "null_action";
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("con_req") || symbol.startsWith("length_resp") || symbol.startsWith("feature_resp") ||
                symbol.startsWith("mtu_resp") || symbol.startsWith("pri_resp") || symbol.startsWith("pair_req") ||
                symbol.startsWith("pair_req_no_sc") || symbol.startsWith("pair_req_no_sc_bonding") || symbol.startsWith("pair_req_oob") ||
                symbol.startsWith("sm_random_send") || symbol.startsWith("dh_check") ||
                symbol.startsWith("pair_confirm") || symbol.startsWith("pair_confirm_wrong_value") ||
                symbol.startsWith("start_enc_resp") ||symbol.startsWith("start_enc_resp_plain") ||
                symbol.startsWith("enc_pause_req") ||symbol.startsWith("enc_pause_resp") ||
                symbol.startsWith("enc_pause_req_plain") ||symbol.startsWith("enc_pause_resp_plain") ||
                symbol.startsWith("dh_check_invalid") || symbol.startsWith("sign_info")) {
            try {
                if(!blesul.config.db_table_name.contains("ll") && !blesul.config.db_table_name.contains("re")) {
                    if (num_symbols_after_pre > 1 && symbol.contains("pair_req")) {
                        System.out.println("Why I reached here!!");
                        //pre();
                        num_symbols_after_pre = 1;
                    }
                }
                if(num_symbols_after_pre > 1 & blesul.config.state_machine.contains("ll")) {
                    if (symbol.contains("con_req")) {
                        pre();
                        return step(symbol);
                    }
                }

                String result1 = "";
                if((last_pair.equals("pair_req_no_sc_keyboard_display") || last_pair.equals("pair_req_no_sc_display_yes_no")) &&
                        symbol.contains("pair_confirm") && !symbol.contains("pair_confirm_wrong_value")) {
                    // blesul.ble_controller_socket.setSoTimeout(10 * 1000);
                    // System.out.println("Sending accept_pair_confirm");
                    //blesul.device_out.write("accept_pair_confirm\n");
                    //blesul.device_out.flush();
                    //String accept_result = blesul.device_in.readLine();
                }
                if((last_pair.equals("pair_req_no_sc_keyboard_display") || last_pair.equals("pair_req_no_sc_display_yes_no"))
                        && symbol.contains("pair_confirm") && !symbol.contains("pair_confirm_wrong_value")) {
                    try {
                        sleep(3000); //50 milliseconds
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    blesul.ble_controller_socket.setSoTimeout(7 * 1000);
                } else {
                    blesul.ble_controller_socket.setSoTimeout(7 * 1000);
                }
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();

                if(symbol.startsWith("pair_req") && !symbol.equals("pair_req_key_zero")){
                    last_pair = symbol;
                    blesul.ble_controller_socket.setSoTimeout(7 * 1000);
                    System.out.println("Sending accept pair");
                    blesul.device_out.write("accept_pair\n");
                    blesul.device_out.flush();
                    String accept_result = blesul.device_in.readLine();

                    System.out.println("DEVICE ACCEPT: " + accept_result);
                }

                if((last_pair.equals("pair_req_display_yes_no")|| last_pair.equals("pair_req_keyboard_display")) && symbol.equals("dh_check")) {
                    blesul.ble_controller_socket.setSoTimeout(10 * 1000);
                    System.out.println("Sending dh_key_confirm");
                }
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
                while (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                        result.contains("char_resp") || result.contains("mtu_req") || result.contains("att_error") ||
                        (result.contains("version_resp") && !symbol.contains("con_req")) || result.contains("ll_reject") || /*result.contains("version_resp") ||*/
                result.contains("feature_req") || result.contains("feature_resp") || result.contains("pri_resp")) {
                    if (symbol.contains("con_req")) {
                        sleep(1);
                        blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                        blesul.ble_controller_out.write(symbol + "\n");
                        blesul.ble_controller_out.flush();
                    }

                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                }
            } catch (SocketTimeoutException e) {
                result = "null_action";
                if(!blesul.config.db_table_name.contains("ll")) {
                    if (symbol.contains("pair_req") && !symbol.contains("pair_req_key_zero") && !symbol.contains("pair_req_oob") && !result.contains("pair_resp")) {
                        System.out.println(symbol + " Not working... Retrying...");
                        //pre();
                        //return step(symbol);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            catch (InterruptedException e) {
                e.printStackTrace();
            }
            if (symbol.startsWith("con_req")){
                try{
                    sleep(3000);
                }
                catch(InterruptedException e){
                    e.printStackTrace();
                }
            }
        } else if (symbol.startsWith("sec_service_req")) {
            try {
                System.out.println("sec_service_req case!");
                String result1 = "";
                blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
                if (!symbol.contains("con_req") && result.contains("version_resp")) {
                    blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                    blesul.ble_controller_out.write(symbol + "\n");
                    blesul.ble_controller_out.flush();
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                }
                while (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                        result.contains("char_resp") || result.contains("version_resp")) {
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                    if (!symbol.contains("con_req") && result.contains("feature_req")) {
                        result = "null_action";
                    }
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                if (!result.startsWith("desc_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("version_req")) {
            try {
                System.out.println("version_req from learner!");
                String result1 = "";
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_socket.setSoTimeout(3 * 1000);
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
                while (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                        result.contains("feature_req")) {
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                    if (!symbol.contains("con_req") && result.contains("feature_req")) {
                        result = "null_action";
                    }
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                if (!result.startsWith("desc_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        else if (symbol.startsWith("length_req") || symbol.startsWith("feature_req")) {
            try {
                // System.out.println("length_req from learner (increased timer)!");
                String result1 = "";
                sleep(500);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_socket.setSoTimeout(7 * 1000);
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
                while (result.contains("feature_req") ||result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") || result.contains("version_resp")) {
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                    // if (!symbol.contains("con_req") && result.contains("feature_req")) {
                    //     result = "null_action";
                    // }
                }
                sleep(1000);
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                result = "null_action";
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("mtu_req")) {
            try {
                System.out.println("mtu_req from learner!");
                String result1 = "";
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_socket.setSoTimeout(6 * 1000);
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
                while (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE")  || result.contains("version_resp") || result.contains("feature_req")) {
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                    if (!symbol.contains("con_req") && result.contains("feature_req")) {
                        result = "null_action";
                    }
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                if (!result.startsWith("desc_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("pri_req")) {
            try {
                String result1 = "";
                blesul.ble_controller_socket.setSoTimeout(8 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("feature_req") ||
                        result.contains("DONE") || result.contains("pri_resp") || result.contains("length_req") ||
                        result.contains("ll_reject") || result.contains("version_resp") || result.contains("mtu_resp")) {
                    while (!result.contains("pri_resp")) {
                        System.out.println("I am in the check case for pri_req!");
                        //ble_controller_socket.setSoTimeout(5 * 1000);
                        blesul.ble_controller_out.write(symbol + "\n");
                        blesul.ble_controller_out.flush();
                        result = blesul.ble_controller_in.readLine();
                    }
                    while (result.contains("pri_resp")) {
                        result1 = blesul.ble_controller_in.readLine();
                        if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                            result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                        }
                        result1 = blesul.getClosests(result1);
                    }
                }
                if (result.contains("adv_ind") || result.contains("feature_req") || result.contains("ll_reject") ||
                        result.contains("char_resp") || result.contains("scan_resp") || result.contains("version_resp")) {
                    result = "null_action";
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol + " with result: " + result);
                if (!result.contains("pri_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("includes_req")) {
            try {
                String result1 = "";
                blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
                if (!symbol.contains("con_req") && result.contains("version_resp")) {
                    blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                    blesul.ble_controller_out.write(symbol + "\n");
                    blesul.ble_controller_out.flush();
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                }
                while (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                        result.contains("char_resp") || result.contains("version_resp")) {
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                    if (!symbol.contains("con_req") && result.contains("feature_req")) {
                        result = "null_action";
                    }
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                if (!result.startsWith("desc_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        else if (symbol.startsWith("key_exchange") || symbol.startsWith("key_exchange_invalid")) {
            try {
                blesul.ble_controller_socket.setSoTimeout(10 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                while (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                       result.contains("char_resp") || result.contains("att_error") ||
                        result.contains("version_resp")||
                        result.contains("feature_req") || result.contains("feature_resp") || result.contains("pri_resp")) {
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                }
                String result1 = "";
                result1 = blesul.ble_controller_in.readLine();
                if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                    result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                }
                result1 = blesul.getClosests(result1);
                while (result1.contains("adv_ind") || result1.contains("scan_resp") || result1.contains("DONE")) {
                    result1 = blesul.ble_controller_in.readLine();
                    if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                        result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                    }
                    result1 = blesul.getClosests(result1);
                }
                if (!result1.isEmpty()) {
                    result = result + "_" + result1;
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol + " with result: " + result);
                if (!result.startsWith("desc_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("enc_req")) {
            String result1 = "";
            try {
                blesul.ble_controller_socket.setSoTimeout(6 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                while (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                         result.contains("char_resp") || result.contains("att_error") ||
                        result.contains("version_resp") ||  result.contains("length_resp") ||
                        result.contains("feature_req") || result.contains("feature_resp") || result.contains("pri_resp")) {
                    result = blesul.ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = blesul.getClosests(result);
                }
                //ble_controller_socket.setSoTimeout(5 * 1000);
                result1 = blesul.ble_controller_in.readLine();
                if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                    result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                }
                result1 = blesul.getClosests(result1);
                while (result1.contains("adv_ind") || result1.contains("scan_resp") || result1.contains("DONE")) {
                    result1 = blesul.ble_controller_in.readLine();
                    if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                        result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                    }
                    result1 = blesul.getClosests(result1);
                }
                if (!result1.isEmpty()) {
                    result = result + "_" + result1;
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                if (!result1.isEmpty() && (result1.equals("ll_reject") || result1.equals("start_enc_req"))) {
                    result = result + "_" + result1;
                } else if (!result.isEmpty() && (result.equals("ll_reject") || result.equals("start_enc_req"))) {
                    result = "enc_resp" + "_" + result;
                } else if (result.contains("adv_ind")) {
                    result = "null_action";
                }
                if (result1.isEmpty() && !result.isEmpty() & !result.equals("null_action")) {
                    if (result.equals("enc_resp")) {
                        result = result + "_" + "ll_reject";
                    }
                }
                if (result.equals("scan_resp") || result.equals("adv_ind")) {
                    System.out.println("Caught scan_resp in enc_req case");
                    result = "null_action";
                }
                if (result.isEmpty()) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("char_req")) {
            try {
                String result1 = "";
                blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.contains("adv_ind") || result.contains("att_error") || result.contains("scan_resp") ||
                        result.contains("DONE") || result.contains("char_resp") || result.contains("mtu_req")  || result.contains("version_resp")) {
                    if (!result.contains("char_resp")) {
                        System.out.println("I am in the check case for char_req!");
                        blesul.ble_controller_socket.setSoTimeout(3 * 1000);
                        blesul.ble_controller_out.write(symbol + "\n");
                        blesul.ble_controller_out.flush();
                    }
                    if (result.contains("mtu_req")) {
                        result = blesul.ble_controller_in.readLine();
                    }
                    result1 = blesul.ble_controller_in.readLine();
                    while (result1.contains("char_resp") || result1.contains("att_error")) {
                        result1 = blesul.ble_controller_in.readLine();
                        if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                            result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                        }
                        result1 = blesul.getClosests(result1);
                    }
                }
                if (result.contains("adv_ind") || result.contains("feature_req")) {
                    result = "null_action";
                } else {
                    if (!result1.isEmpty()) {
                        result = result;//+ "_" + result1;
                    }
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol + " result: " + result);
                if (!result.startsWith("char_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("desc_req")) {
            try {
                String result1 = "";
                blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                        result.contains("desc_resp") || result.contains("length_req") || result.contains("ll_reject") ||
                        result.contains("att_error") || result.contains("version_resp")) {
                    if (!result.contains("desc_resp")) {
                        System.out.println("I am in the check case for desc_req!");
                        //ble_controller_socket.setSoTimeout(5 * 1000);
                        blesul.ble_controller_out.write(symbol + "\n");
                        blesul.ble_controller_out.flush();
                        result = blesul.ble_controller_in.readLine();
                    }
                    while (result.contains("desc_resp")) {
                        result1 = blesul.ble_controller_in.readLine();
                        if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                            result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                        }
                        result1 = blesul.getClosests(result1);
                    }
                }
                if (result.contains("DONE") || result.contains("adv_ind") || result.contains("feature_req") ||
                        result.contains("ll_reject") || result.contains("char_resp") || result.contains("scan_resp")) {
                    result = "null_action";
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol + " with result: " + result);
                if (!result.contains("desc_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("read")) {
            try {
                String result1 = "";
                blesul.ble_controller_socket.setSoTimeout(4 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.contains("desc_resp") || result.contains("read_resp") || result.contains("adv_ind") ||
                        result.contains("scan_resp") || result.contains("DONE") || result.contains("att_error") ||
                        result.contains("char_resp") || result.contains("version_resp")) {
                    System.out.println("I am in the check case for read IKkkkkk!");
                    //ble_controller_socket.setSoTimeout(5 * 1000);
                    if (!result.contains("read_resp")) {
                        blesul.ble_controller_out.write(symbol + "\n");
                        blesul.ble_controller_out.flush();
                    }
                    result = blesul.ble_controller_in.readLine();
                    while (result.contains("read_resp")) {
                        System.out.println("I am in the check case for looping!");
                        result1 = blesul.ble_controller_in.readLine();
                        if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                            result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                        }
                        result1 = blesul.getClosests(result);
                    }
                }
                if (result.contains("adv_ind") || result.contains("feature_req") || result.contains("DONE") ||
                        result.contains("scan_resp") || result.contains("version_resp") ) {
                    result = "null_action";
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                if (!result.startsWith("read_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (symbol.startsWith("write")) {
            try {
                String result1 = "";
                blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                result = blesul.ble_controller_in.readLine();
                if (result.contains("adv_ind") || result.contains("scan_resp") || result.contains("DONE") ||
                        result.contains("char_resp") || result.contains("version_resp")) {
                    System.out.println("I am in the check case for write!");
                    blesul.ble_controller_socket.setSoTimeout(5 * 1000);
                    blesul.ble_controller_out.write(symbol + "\n");
                    blesul.ble_controller_out.flush();
                    result = blesul.ble_controller_in.readLine();
                    while (result.contains("write_resp")) {
                        result1 = blesul.ble_controller_in.readLine();
                        if (result1.compareTo("") != 0 && result1.toCharArray()[0] == ' ') {
                            result1 = new String(Arrays.copyOfRange(result1.getBytes(), 1, result1.getBytes().length));
                        }
                        result1 = blesul.getClosests(result);
                    }
                }
                if (result.contains("adv_ind") || result.contains("feature_req") || result.contains("scan_resp") ||
                        result.contains("DONE") || result.contains("version_resp")) {
                    result = "null_action";
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                if (!result.startsWith("write_resp")) {
                    result = "null_action";
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                System.out.println("Else case Symbol: " + symbol);
                blesul.ble_controller_out.write(symbol + "\n");
                blesul.ble_controller_out.flush();
                blesul.ble_controller_socket.setSoTimeout(3 * 1000);
                result = blesul.ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = blesul.getClosests(result);
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occured for " + symbol);
                result = "null_action";
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (result.equals("att_error")) {
            System.out.println("Caught att_error, replacing with null_action");
            result = "null_action";
        }
        if (symbol.contains("enc_req") && !result.equals("null_action")) {
            List<String> resultList = Arrays.asList(result.split("_"));
            if (resultList.get(0).equals("att_error") && resultList.get(1).equals("enc_resp")) {
                System.out.println("reversed order!");
                result = resultList.get(1) + "_" + resultList.get(0);
            }
        }
        if (result.equals("mtu_req")) {
            System.out.println("Caught mtu_req, replaced with null_action");
            result = "null_action";
        }
        if(symbol.contains("con_req") && result.equals("version_resp")) {
            System.out.println("Caught version_resp for con_req, replaced with null_action");
            result = "null_action";
        }
        if (result.equals("feature_req")) {
            System.out.println("Caught feature_req, replaced with null_action");
            result = "null_action";
        }
        if(result.equals("enc_resp_ll_reject")) {
            System.out.println("Caught enc_resp_ll_reject");
            result = "null_action";
        }
        if(result.equals("DONE")) {
            result = "null_action";
        }
        if(symbol.contains("discon_req")) {
            try {
                TimeUnit.SECONDS.sleep(3);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            blesul.reset_ble();
        }
        System.out.println(symbol + "->" + result);
        return result;
    }

}
