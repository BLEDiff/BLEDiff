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

import ble.statelearner.ble.BLEConfig;
import ble.statelearner.ble.BLESUL;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LogExecutor {
    BLEConfig config;
    BLESUL sul;
    Socket mme_socket, enodeb_socket, ue_socket;
    BufferedWriter mme_out, enodeb_out, ue_out;
    BufferedReader mme_in, enodeb_in, ue_in;


    private static final String[] expectedResults = {"scan_resp",
            "adv_ind",
            "feature_req",
            "feature_resp",
            "length_resp",
            "length_req",
            "mtu_req",
            "version_resp",
            "pair_resp_no_sc",
            "pair_resp",
            "enc_resp",
            "start_enc_req",
            "char_req",
            "pri_resp",
            "pri_req",
            "public_key_response",
            "sm_confirm",
            "sm_random_received",
            "dh_key_response",
            "start_enc_resp",
            "char_resp",
            "att_error",
            "desc_resp",
            "read_resp",
            "mtu_resp",
            "DONE"};

    public LogExecutor(BLESUL sul) throws Exception {
        this.sul = sul;
    }

    public void run(String[] args) {
        List<List<String>> queries = new ArrayList<>();

        if (args[0].contains("-f")) {
            System.out.println("file");

            if(args.length > 0) {
                String file_name = args[1];
                try (BufferedReader br = new BufferedReader(new FileReader(file_name))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        if (line.contains("INFO")) {
                            line = line.split("/")[0].split("\\[")[1].replaceAll("\\|", " ");
                            //System.out.println(line);
                            List<String> split_line = Arrays.asList(line.split("\\s+"));
                            /*
                            for (int i=0; i<split_line.size(); i++){
                                System.out.println(split_line.get(i));
                            }
                            \*/
                            queries.add(split_line);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            System.out.println(queries.size());

            Boolean time_out_occured = false;

            Integer querry_num = 1;

            for (List<String> query: queries){

                Boolean exception_occured = execute_query(query);

                while (exception_occured) {
                    exception_occured = execute_query(query);
                }

                System.out.println("Finished Query # " + Integer.toString(querry_num));
                querry_num ++;
            }

        } else if (args[0].contains("-q")) {
            System.out.println("query");
            System.out.println(args[1]);
            String line = args[1];
            System.out.println("query: " + line);
            List<String> split_line = Arrays.asList(line.split("\\s+"));

            for(String word: split_line){
                System.out.println(word);
            }


            Boolean time_out_occured = false;

            this.sul.pre();

            boolean enb_alive = true;

            do {
                for (String command: split_line) {
                    if (command.contains("ε"))
                        continue;

                    if (time_out_occured) {
                        System.out.println("RESULT: NULL ACTION");
                        continue;
                    }

                    String result = this.sul.step(command);
                    result = getClosests(result);

                    if (result.matches("timeout")){
                        time_out_occured = true;
                        System.out.println("RESULT: NULL ACTION(TIMEOUT)");
                        continue;
                    }

                    System.out.println("RESULT: " + result);
                }

            } while(!enb_alive);



        } else {
            System.out.println("Invalid command line arguments");
        }

    }

    public Boolean execute_query(List<String> query) {
        this.sul.pre();
        boolean time_out_occured = false;

        boolean exception_occured = false;

        boolean enb_alive = true;

        do {
            for (String command: query) {
                if (command.contains("ε"))
                    continue;
                System.out.println("COMMAND: " + command);

                if (time_out_occured) {
                    System.out.println("RESULT: NULL ACTION");
                    continue;
                }

                command = command.replaceAll("\\s+","");
                String result = this.sul.step(command);

                if (result.matches("EXCEPTION")) {
                    System.out.println("Exception occured, restarting query");
                    exception_occured = true;
                }

                //TODO: Add Levenshtein Distance method here

                result = getClosests(result);

                if (result.matches("timeout")){
                    time_out_occured = true;
                    System.out.println("RESULT: NULL ACTION(TIMEOUT)");
                    continue;
                }

                System.out.println("RESULT: " + result);
            }


        } while(!enb_alive);

        return exception_occured;
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
                distance[i][j] = minimum(
                        distance[i - 1][j] + 1,
                        distance[i][j - 1] + 1,
                        distance[i - 1][j - 1] + ((lhs.charAt(i - 1) == rhs.charAt(j - 1)) ? 0 : 1));

        return distance[lhs.length()][rhs.length()];
    }

    public String getClosests(String result) {
        System.out.println("Getting closest of " + result);

        if (Arrays.asList(expectedResults).contains(result)) {
            return result;
        }

        int minDistance = Integer.MAX_VALUE;
        String correctWord = null;

        for (String word: Arrays.asList(expectedResults)) {
            int distance = computeLevenshteinDistance(result, word);

            if (distance < minDistance) {
                correctWord = word;
                minDistance = distance;
            }
        }

        return correctWord;
    }
}

