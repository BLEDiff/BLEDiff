package ble.statelearner.ble;

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


import java.io.*;
import java.net.*;
import java.sql.Time;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import static java.lang.Thread.sleep;

import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;
import de.learnlib.api.SUL;

import ble.statelearner.StateLearnerSUL;
import ble.statelearner.SlaveAddressFinder;
import ble.statelearner.ble.devices.*;



public class BLESUL implements StateLearnerSUL<String, String> {
    private static final String[] WIN_RUNTIME = {"cmd.exe", "/C"};
    private static final String[] OS_LINUX_RUNTIME = {"/bin/bash", "-l", "-c"};
    private static final List<String> expectedResults = Arrays.asList("scan_resp", "adv_ind", "feature_req",
            "feature_resp", "length_resp", "length_req", "mtu_req", "version_resp", "pair_resp", "char_req", "ll_reject", "mtu_resp",
            "enc_resp", "start_enc_req", "pri_resp", "public_key_response", "sm_confirm", "sm_random_received",
            "dh_key_response", "start_enc_resp", "pri_req", "char_resp", "att_error", "desc_resp", "read_resp", "enc_pause_resp", "sec_req","pair_resp_no_sc",
            "DONE");
    private static final List<String> scan_req_expectedResults = Arrays.asList("scan_resp", "null_action");
    public SlaveAddressFinder slaveAddressFinder;
    public BLEConfig config;
    public SimpleAlphabet<String> alphabet;
    public Socket ble_controller_socket, device_socket;
    public BufferedWriter ble_controller_out, device_out;
    public BufferedReader ble_controller_in, device_in;

    private Device_SUL device_sul;


    public BLESUL(BLEConfig config) throws Exception {
        this.config = config;
        alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));

        System.out.println("Starting BLE Controller");
        init_ble_controller();
        init_device_con();
        slaveAddressFinder = new SlaveAddressFinder(this.config.device_adv_name);

        device_sul = Device_SUL_Factory.get_Device_SUL(config.device, this, this.config.state_machine);
        if (device_sul == null){
            System.out.println("config.device is wrong, or not handled in Device_SUL_Factory. Exiting...");
            System.exit(1);
        }

        System.out.println("Done with initializing the connection with BLE Controller and Device Controller");

    }

    private static <T> T[] concat(T[] first, T[] second) {
        T[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public SimpleAlphabet<String> getAlphabet() {
        return alphabet;
    }

    public boolean canFork() {
        return false;
    }

    public SUL<String, String> fork() throws UnsupportedOperationException {
        throw new UnsupportedOperationException("Cannot fork SocketSUL");
    }

    public void post() {
        device_sul.post();
    }

    public String step(String symbol) {
        return device_sul.step(symbol);
    }

    public String reset_ble() {
        String result = new String("");
        System.out.println("Sending symbol: RESET to BLE controller");
        try {
            ble_controller_out.write("RESET " + "\n");
            ble_controller_out.flush();
            ble_controller_socket.setSoTimeout(20 * 1000);

            while (result.equalsIgnoreCase("") || result.equalsIgnoreCase("adv_ind") || result.equalsIgnoreCase("scan_resp")) {    //multiple adv_ind in the
                // pipe. consume them.
                result = ble_controller_in.readLine();
            }
            System.out.println("ACK for RESET_BLE: " + result);
            if (!result.startsWith("DONE")) {
                sleep(15 * 1000);
                reset_ble();
            }
        }catch (SocketTimeoutException e){
            System.out.println("Timeout occurred!!! Retrying...");
            return reset_ble();
        }
        catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }

    public String reset_device() {
        String result = new String("");
        System.out.println("Sending symbol: RESET to Device controller");

        try {
            sleep(1 * 1000);
            device_out.write("RESET\n");
            device_out.flush();
            result = device_in.readLine();
            System.out.println("ACK for RESET_DEVICE: " + result);
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public boolean needSlaveAddressUpdate() {
        String result = "";
        int MAX_TRY = 3;
        for (int i = 0; i < MAX_TRY; i++) {
            System.out.println("Trying to send scan_req. Iteration: " + i);
            try {
                while (!result.contains("scan_resp") && !result.contains("adv_ind")) {
                    ble_controller_socket.setSoTimeout(3 * 1000);
                    ble_controller_out.write("scan_req" + "\n");
                    ble_controller_out.flush();
                    result = ble_controller_in.readLine();
                    if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                        result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                    }
                    result = getClosests(result);
                }
            } catch (SocketTimeoutException e) {
                System.out.println("Timeout occurred for scan_req");
                result = "null_action";
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (!result.equalsIgnoreCase("null_action")) {
                return false;
            }
        }
        return true;
    }

    public boolean sendSlaveAddress() {
        System.out.println("Trying to find new slave address...");

        boolean updated = slaveAddressFinder.findAddress(15, device_in, device_out);
        if (!updated) {
            System.out.println("Slave address not changed.");
            return false;
        }
        String slaveAddress = slaveAddressFinder.getDeviceAddress();

        try {
            ble_controller_socket.setSoTimeout(15 * 1000);
            ble_controller_out.write("update_slave_address-" + slaveAddress + "\n");
            ble_controller_out.flush();
            String result = "";
            while (result.equalsIgnoreCase("") || result.equalsIgnoreCase("adv_ind") || result.equalsIgnoreCase(
                    "scan_resp") || result.equalsIgnoreCase("version_resp")) {
                result = ble_controller_in.readLine();
                if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
                    result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
                }
                result = getClosests(result);
            }
            if (result.equalsIgnoreCase("DONE")) {
                System.out.println("Slave address updated successfully");
                return true;
            }
        } catch (SocketTimeoutException e) {
            System.out.println("Timeout occurred for " + "update_slave_address");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public void pre() {
        device_sul.pre();
    }

    public boolean post_query_check() throws InterruptedException {
        return true;
    }

    public void init_ble_controller() {
        try {
            // Initialize test service
            System.out.println("Connecting to BLE Controller...");
            ble_controller_socket = new Socket(config.ble_controller_ip_address, config.ble_controller_port);
            ble_controller_socket.setTcpNoDelay(true);
            ble_controller_out = new BufferedWriter(new OutputStreamWriter(ble_controller_socket.getOutputStream()));
            ble_controller_in = new BufferedReader(new InputStreamReader(ble_controller_socket.getInputStream()));
            System.out.println("Connected to BLE Controller.");
        } catch (UnknownHostException e) {
            e.printStackTrace();
            init_ble_controller();
        } catch (SocketException e) {
            e.printStackTrace();
            init_ble_controller();
        } catch (Exception e) {
            e.printStackTrace();
            init_ble_controller();
        }
        System.out.println("Connected to BLE Controller.");
    }

    public void init_device_con() {
        try {
            System.out.println("Connecting to device controller...");
            System.out.println("Device controller IP Address: " + config.device_controller_ip_address);
            device_socket = new Socket(config.device_controller_ip_address, config.device_controller_port);
            device_socket.setTcpNoDelay(true);
            //device_socket.setSoTimeout(180*1000);
            System.out.println("Connected to Device Controller");

            System.out.println("Initializing Buffers for Device Controller...");
            device_out = new BufferedWriter(new OutputStreamWriter(device_socket.getOutputStream()));
            device_in = new BufferedReader(new InputStreamReader(device_socket.getInputStream()));
            System.out.println("Initialized Buffers for BLE Device");

        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public int minimum(int a, int b, int c) {
        return Math.min(Math.min(a, b), c);
    }

    public int computeLevenshteinDistance(CharSequence lhs, CharSequence rhs) {
        int[][] distance = new int[lhs.length() + 1][rhs.length() + 1];

        for (int i = 0; i <= lhs.length(); i++)
            distance[i][0] = i;
        for (int j = 1; j <= rhs.length(); j++)
            distance[0][j] = j;

        for (int i = 1; i <= lhs.length(); i++)
            for (int j = 1; j <= rhs.length(); j++)
                distance[i][j] = minimum(distance[i - 1][j] + 1, distance[i][j - 1] + 1,
                        distance[i - 1][j - 1] + ((lhs.charAt(i - 1) == rhs.charAt(j - 1)) ? 0 : 1));

        return distance[lhs.length()][rhs.length()];
    }

    public String getClosests(String result) {
        if (!result.contains("adv_ind")){
            System.out.println("Getting closest of " + result);
        }
        else {
            System.out.print("adv_ind ");
        }
        if (expectedResults.contains(result)) {
            return result;
        }

        int minDistance = Integer.MAX_VALUE;
        String correctWord = null;


        for (String word : expectedResults) {
            int distance = computeLevenshteinDistance(result, word);

            if (distance < minDistance) {
                correctWord = word;
                minDistance = distance;
            }
        }
        return correctWord;
    }

    public String getExpectedResult(String symbol, String result) {

        String final_result = "null_action";

        if (symbol.contains("scan_req")) {
            if (scan_req_expectedResults.contains(result)) {
                final_result = result;
            }
        }
        return final_result;
    }

    public boolean context_check(String symbol, boolean discon_req_sent, boolean con_req_after_reset, boolean pair_req_after_reset){
        // these packets will be sent anytime from step
        if(symbol.contains("scan_req") || symbol.contains("con_req")  || symbol.contains("discon_req")){
            return true;
        }

        // no packets after discon req
        if(discon_req_sent){
            return false;
        }

        // if not discon_req_sent, send pair_req anytime
        if(symbol.contains("pair_req")){
            return true;
        }

        // link layers packets context check
        if(symbol.contains("feature_req") || symbol.contains("feature_resp") ||
                symbol.contains("mtu_req") || symbol.contains("mtu_resp") || symbol.contains("length_req") ||
                symbol.contains("length_resp") || symbol.contains("version_req") || symbol.contains("version_resp") ||
                symbol.contains("pri_req")){
            return con_req_after_reset;
        }

        // no smp packet without pair req already sent
        if(!pair_req_after_reset){
            return false;
        }

        return true;    

    }

}