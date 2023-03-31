package ble.statelearner;

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
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

public class SlaveAddressFinder {
    private static final long SCAN_TIME = 8000L;
    private static final int MAX_TEST = 3;
    private static final int MAX_TRY = 3;

    private String deviceName;
    private String deviceAddress;
    private BufferedReader deviceReader;
    private BufferedWriter deviceWriter;

    public SlaveAddressFinder(String deviceName) {
        System.out.println("SlaveAddressFinder for device: " + deviceName);
        this.deviceName = deviceName;
        this.deviceAddress = "00:00:00:00:00:00";
    }

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    public String getDeviceAddress() {
        return deviceAddress;
    }

    public void setDeviceAddress(String deviceAddress) {
        this.deviceAddress = deviceAddress;
    }

    private boolean reset_blueZ(int timeoutSeconds){
        try{
            ProcessBuilder processBuilder = new ProcessBuilder("./remove_bluetooth_devices.sh");
            Process process = processBuilder.start();
            process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            Scanner scanner = new Scanner(process.getInputStream());
            ProcessBuilder processBuilder1 = new ProcessBuilder("./off-brder.sh");
            Process process1 = processBuilder.start();
            process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            Scanner scanner1 = new Scanner(process.getInputStream());
//            while (scanner.hasNextLine()) System.out.println("Reset: " + scanner.nextLine());

        }
        catch (Exception e){
            e.printStackTrace();
        }
        return true;
    }

    private boolean findAddressWithName(int timeoutSeconds){
        // resetting bluetooth devices. Otherwise wrong address may come up
        this.reset_blueZ(timeoutSeconds);

        try{
            ProcessBuilder processBuilder = new ProcessBuilder("bluetoothctl");
            Process process = processBuilder.start();
            InputStream is = process.getInputStream();
            Scanner scanner = new Scanner(is);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(process.getOutputStream());

            outputStreamWriter.write("scan on\n");
            outputStreamWriter.flush();

            long timeoutAt = System.currentTimeMillis() + timeoutSeconds * 1000L;
            while (System.currentTimeMillis() <= timeoutAt){
                while (is.available() > 0){
                    String line = scanner.nextLine();
//                    System.out.println("PROCESS OUTPUT: " + line);
                    if(!line.contains(this.getDeviceName())){
                        continue;
                    }
                    String [] lineParts = line.split("\\s+");
                    if (lineParts[1].equals("Device")){
                        process.destroy();
                        String newAddress = lineParts[2].toLowerCase();
                        if(this.getDeviceAddress().equalsIgnoreCase(newAddress)){ return false; }
                        else{
                            this.setDeviceAddress(newAddress);
                            return true;
                        }
                    }
                }
                Thread.sleep(500);
            }
            process.destroy();
        }
        catch (Exception e){ e.printStackTrace(); }
        return false;
    }

    private HashSet<String> getAvailableDevices(int timeoutSeconds){
        HashSet<String> devices = new HashSet<String>();
        this.reset_blueZ(timeoutSeconds);

        try{
            ProcessBuilder processBuilder = new ProcessBuilder("bluetoothctl");
            Process process = processBuilder.start();
            InputStream is = process.getInputStream();
            Scanner scanner = new Scanner(is);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(process.getOutputStream());

            outputStreamWriter.write("scan on\n");
            outputStreamWriter.flush();

            long timeoutAt = System.currentTimeMillis() + SCAN_TIME;
            while (System.currentTimeMillis() <= timeoutAt){
                while (is.available() > 0){
                    String line = scanner.nextLine();
//                    System.out.println("PROCESS OUTPUT: " + line);
                    if(!line.contains("NEW") || !line.contains("Device")){
//                        System.out.println("IGNORED LINE: " + line);
                        continue;
                    }
                    String [] lineParts = line.split("\\s+");
                    devices.add(lineParts[2].toLowerCase());
                }
//                Thread.sleep(500);
            }
            process.destroy();
        }
        catch (Exception e){ e.printStackTrace(); }

//        System.out.println("IN getAvailableDevices");
//        for (Object address: devices.toArray()) {
//            System.out.println("devices : " + address.toString());
//        }

        return devices;
    }

    private HashSet <String> setDifference(HashSet <String> set1, HashSet <String> set2){
        HashSet <String> result = new HashSet<String>(set1);
        result.removeAll(set2);
        return result;
    }

    private boolean turnOffDevice(){
        try{
            Thread.sleep(500);
            this.deviceWriter.write("turn_off_device\n");
            this.deviceWriter.flush();

            String result = this.deviceReader.readLine().trim();
            return result.equalsIgnoreCase("DONE");
        }
        catch (Exception e){ e.printStackTrace(); }
        return false;
    }

    private boolean turnOnDevice(){
        try{
            Thread.sleep(500);
            this.deviceWriter.write("turn_on_device\n");
            this.deviceWriter.flush();

            String result = this.deviceReader.readLine().trim();
            return result.equalsIgnoreCase("DONE");
        }
        catch (Exception e){ e.printStackTrace(); }
        return false;
    }

    private boolean findAddressWithoutName(int timeoutSeconds, int test_num){
        if(test_num > MAX_TEST) return false;

        HashSet<String> candidates = new HashSet<String>();

        for (int i = 0; i < MAX_TEST; i++) {
            boolean done = this.turnOffDevice();
            System.out.println("Turn off successful: " + done);
            HashSet <String> beforeDeviceSet = this.getAvailableDevices(timeoutSeconds);

            for (Object address: beforeDeviceSet.toArray()) {
                System.out.println("beforeDeviceSet in try " + i + " : " + address.toString());
            }

            done = this.turnOnDevice();
            System.out.println("Turn on successful: " + done);
            HashSet <String> afterDeviceSet = this.getAvailableDevices(timeoutSeconds);

            for (Object address: afterDeviceSet.toArray()) {
                System.out.println("afterDeviceSet in try " + i + " : " + address.toString());
            }

            if(candidates.isEmpty()){
                candidates = this.setDifference(afterDeviceSet, beforeDeviceSet);
            }
            else{
                candidates.retainAll(this.setDifference(afterDeviceSet, beforeDeviceSet));
            }

            for (Object address: candidates.toArray()) {
                System.out.println("candidates in try " + i + " : " + address.toString());
            }
        }

        if(candidates.size() == 1){
            String newAddress = candidates.toArray()[0].toString().toLowerCase();
            if(this.getDeviceAddress().equalsIgnoreCase(newAddress)){ return false; }
            else{
                this.setDeviceAddress(newAddress);
                return true;
            }
        }

        return this.findAddressWithoutName(timeoutSeconds, test_num+1);
    }

    public boolean findAddress(int timeoutSeconds, BufferedReader deviceReader, BufferedWriter deviceWriter){
        this.deviceReader = deviceReader;
        this.deviceWriter = deviceWriter;
        // this boolean return value lessens the number of times address is updated and reduces time overhead
        boolean updatedAddress = false;
        if(this.getDeviceName().trim().equalsIgnoreCase("UNK")){
            updatedAddress = findAddressWithoutName(timeoutSeconds, 0);
        }
        else{
            updatedAddress = findAddressWithName(timeoutSeconds);
        }
        return updatedAddress;
    }

}
