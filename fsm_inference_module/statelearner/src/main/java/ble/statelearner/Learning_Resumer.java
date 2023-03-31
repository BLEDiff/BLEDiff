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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;


public class Learning_Resumer {
    String learning_log = "";
    String plain_replay_log = "";
    Map<String, String> learning_map = null;
    public LearningConfig config = null;
    Statement myStmt = null;

    public String getMD5(String password) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashInBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();


    }


    public Learning_Resumer(String learning_log, String plain_replay_log){

        this.learning_log = learning_log;
        this.plain_replay_log = plain_replay_log;
        try{
            config = new LearningConfig("src/ble.properties");
        }
        catch (Exception e){
            System.out.println(e.getMessage());
            System.out.println("Properties not loaded");
        }
        load_learning_log();

    }

    public Connection getResumerConnection(){
        return DBHelper.getConnection();
    }


    private void load_learning_log(){
        Connection myConn = this.getResumerConnection();
        if (myConn == null){
            System.out.println("***** IN Learning_Resumer.load_learning_log(): RESUMER CONNECTION NULL *****");
        }
        //System.out.println("I am not in!");

        learning_map = new HashMap<>();
        try{

            String sql = "SELECT * FROM queryNew_"+ config.db_table_name ;
            Statement stmt = myConn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
        }catch (Exception e) {
            System.out.println("$$$$$$$$$$$$$$$$$");
            try {
                String create = "CREATE TABLE \"queryNew_"+config.db_table_name+"\""+"(\"id\"	TEXT,\"command\"	TEXT,\"resultHash\"	TEXT,\"result\"	TEXT,\"prefLen\"	INTEGER, PRIMARY KEY(\"id\"))";
                Statement stmt = myConn.createStatement();
                stmt.executeUpdate(create);
            }catch (Exception ex){
                System.out.println("Failed to create table");
            }
        }
        try{

            String sql = "SELECT * FROM query_"+ config.db_table_name ;
            Statement stmt = myConn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
        }catch (Exception e) {
            System.out.println("$$$$$$$$$$$$$$$$$");
            try {
                String create = "CREATE TABLE \"query_"+config.db_table_name+"\""+"(\"id\"	TEXT,\"command\"	TEXT,\"resultHash\"	TEXT,\"result\"	TEXT,\"prefLen\"	INTEGER, PRIMARY KEY(\"id\"))";
                Statement stmt = myConn.createStatement();
                stmt.executeUpdate(create);
            }catch (Exception ex){
                System.out.println("Failed to create table");
            }
        }
        try {

            //check query* is empty or not
            String sql = "SELECT * FROM queryNew_" + config.db_table_name;
            Statement stmt = myConn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                //System.out.println("I am in!");
                //There are some entry in query*
                //Copy everything from query* in query
                Statement st = myConn.createStatement();

                //String s= "INSERT INTO query (id,command,resultHash,result) SELECT id,command,resultHash,result FROM queryNew queryNew.id NOT IN (SELECT id FROM query)";
                //st.executeUpdate(s);
                //st.executeUpdate("INSERT INTO query SELECT (id,command,resultHash,result) FROM queryNew WHERE NOT EXISTS(SELECT * FROM query WHERE (query.id=queryNew.id))");
                Statement st1 = myConn.createStatement();
                rs = st1.executeQuery("select * from queryNew_"+config.db_table_name);
                PreparedStatement ps = null;

                while (rs.next()) {
                    try {
                        ps = myConn.prepareStatement("insert into query_"+config.db_table_name+ " (id, command, resultHash, result, prefLen) values(?,?,?,?,?)");
                       // System.out.println("data here "+rs.getString("id"));
                        ps.setString(1, rs.getString("id"));
                        ps.setString(2, rs.getString("command"));
                        ps.setString(3, rs.getString("resultHash"));
                        ps.setString(4, rs.getString("result"));
                        ps.setInt(5, rs.getInt("prefLen"));
                        ps.executeUpdate();
                        ps.close();
                    } catch (SQLException e) {
                        //System.out.println("Duplicate Entry!");
                        //e.printStackTrace();
                        //Got a duplicate basically
                    }
                }

                //Delete everything from query*
                sql = "delete from queryNew_" + config.db_table_name;
                st.executeUpdate(sql);
                System.out.println("Deleted all entries in queryNew");
                st1.close();
                stmt.close();
            }
            File f = new File(this.learning_log);
            File f1 = new File(this.plain_replay_log);
            if (f.createNewFile()) {

                System.out.println(this.learning_log + " file has been created.");
                System.out.println(this.plain_replay_log + " file has been created.");
            } else {

                System.out.println(this.learning_log + " file already exists.");
                System.out.println("Reading learning log: " + this.learning_log);
                System.out.println(this.plain_replay_log + " file already exists.");
                System.out.println("Reading learning log: " + this.plain_replay_log);
                PrintWriter writer = new PrintWriter(f);
                PrintWriter writer1 = new PrintWriter(f1);
                writer.print("");
                writer.close();
                writer1.print("");
                writer1.close();
            }
              /*  String line;
                while ((line = br.readLine()) != null) {
                    System.out.println("log: " + line);
                    if (line.contains("INFO")) {
                            String command = line.split("/")[0].split("\\[")[1];
                            String result = line.split("/")[1].split("]")[0];
                            command = String.join(" ", command.split("\\s+"));
                            result = String.join(" ", result.split("\\s+"));
                            learning_map.put(command, result);
                            command = command.replaceAll("\\|"," ");
                            result = result.replaceAll("\\|"," ");
                            System.out.println("IN RESUMER: " + command + "/" + result);
                        try {
                            String query = " insert into query (id, command, resultHash, result)"
                                    + " values (?, ?, ? ,?)";
                            PreparedStatement preparedStmt = myConn.prepareStatement(query);
                            preparedStmt.setString(1, getMD5(command));
                            preparedStmt.setString(2, command);
                            preparedStmt.setString(3, getMD5(result));
                            preparedStmt.setString(4, result);
                            preparedStmt.execute();
                        }catch (SQLException e){
                            System.out.println("history already exist");
                        }

                    }
                }

            }*/

//            myConn.close();

        }catch (IOException e){
            e.printStackTrace();
        }catch (SQLException e) {
            System.err.println("Duplicate Entry!");
            e.printStackTrace();
        }

    }

    public String query_resumer(String command, int prefLen) {
        Connection myConn = this.getResumerConnection();
        if (myConn == null){
            System.out.println("***** IN Learning_Resumer.query_resumer(): RESUMER CONNECTION NULL *****");
        }

        System.out.println("In query resumer, looking for: " + command);
        String query = "select * from query_"+config.db_table_name+" where id = ? and prefLen = ?";
        command = command.replaceAll("\\|"," ");
        try{               
            PreparedStatement preparedstatement = myConn.prepareStatement(query);
            String commandPlusLen = command+prefLen;
            preparedstatement.setString (1, getMD5(commandPlusLen));
            preparedstatement.setInt (2, prefLen);
            ResultSet rs=preparedstatement.executeQuery();
            if(rs.next()){
                //System.out.println("##################################################################### in Resumer!");
                String fromDB = rs.getString("result");
                //System.out.println("resumer!! "+ fromDB);
                //String[] wordList = fromDB.split("\\s+");
                //String suffix = wordList[wordList.length-1];
                //String prefix = fromDB.replaceAll(" "+suffix,"");
                String[] splited = fromDB.split(" ");
                System.out.println("IK: "+ fromDB+splited.length);
                String prefix = "";
                String suffix = "";
                System.out.println("IK "+prefLen);
                prefix = splited[0];
                for(int i=1;i <prefLen; i++){
                    prefix+= " "+ splited[i];
                }
                suffix = splited[prefLen];
                if(prefLen+1<fromDB.length()) {
                    for (int i = prefLen + 1; i < splited.length; i++) {
                        suffix += " " + splited[i];
                    }
                }



                //String prefix = fromDB.substring(0, fromDB.lastIndexOf(" "));
                //String suffix = fromDB.substring(fromDB.lastIndexOf(" ") + 1);
                System.out.println("found in log "+prefix+"|"+suffix);
                //Add this to queryNew

                try{
                    String query2 = " insert into queryNew_"+config.db_table_name+ " (id, command, resultHash, result, suffLen)"
                            + " values (?, ?, ? ,?, ?)";
                    PreparedStatement preparedstatement2 = myConn.prepareStatement(query2);
                    preparedstatement2.setString(1, rs.getString("id"));
                    preparedstatement2.setString(2, rs.getString("command"));
                    preparedstatement2.setString(3, rs.getString("resultHash"));
                    preparedstatement2.setString(4, rs.getString("result"));
                    preparedstatement2.setInt(5, rs.getInt("suffLen"));
                    preparedstatement2.execute();
                    //myConn.close();
                    preparedstatement.close();
                    preparedstatement2.close();
                }catch (Exception e){
//                    myConn.close();
                    System.out.println("Already exists in queryNew!");
                }
//                myConn.close();
                return prefix+"|"+suffix;
            }else{
                return null;
            }
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }

    
    /*
        if (learning_map.containsKey(command)) {
            return learning_map.get(command);
        } else {
            return null;
        }
    */ 
          
    }

    public void add_Entry(String entry, int prefLen) {
        Connection myConn = this.getResumerConnection();
        if (myConn == null){
            System.out.println("***** IN Learning_Resumer.add_Entry(): RESUMER CONNECTION NULL *****");
        }

        System.out.println("In add!");
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(this.learning_log, true))){
            bw.append(entry + '\n');
             
        } catch (Exception e){
            System.err.println("ERROR: Could not update learning log");

        }
        try(BufferedWriter bw1 = new BufferedWriter(new FileWriter(this.plain_replay_log, true))){
            String command = entry.split("/")[0].split("\\[")[1];
            String result = entry.split("/")[1].split("]")[0];
            command = String.join(" ", command.split("\\s+"));
            result = String.join(" ", result.split("\\s+"));
            command = command.replaceAll("\\|"," ");
            result = result.replaceAll("\\|"," ");
            String[] splited_command = command.split(" ");
            String[] splited_result = result.split(" ");
            for (int i=0;i<splited_command.length;i++){
                //dl_nas_transport_plain
                //auth_request_replay
                //security_mode_command_replay
                //GUTI_reallocation_replay
                // dl_nas_transport_replay
                //rrc_reconf_replay
                //rrc_security_mode_command_replay
                //GUTI_reallocation_plain
                if(splited_command[i].startsWith("pair_req_no_sc")||
                        splited_command[i].startsWith("pair_req_no_sc_bonding")||
                        splited_command[i].startsWith("pair_req_oob")||
                        splited_command[i].startsWith("pair_req_key_zero")||
                        splited_command[i].startsWith("key_exchange_invalid")||
                        splited_command[i].startsWith("dh_check_invalid") ||
                        splited_command[i].startsWith("pair_confirm_wrong_value") ||
                        splited_command[i].startsWith("start_enc_resp_plain") ||
                        splited_command[i].startsWith("enc_pause_req_plain") ||
                        splited_command[i].startsWith("feature_req_none") ||
                        splited_command[i].startsWith("mtu_req_llid_zero") ||
                        splited_command[i].startsWith("mtu_req_mtu_zero") ||
                        splited_command[i].startsWith("length_req_time_zero") ||
                        splited_command[i].startsWith("length_req_rx_tx_zero") ||
                        splited_command[i].startsWith("con_req_interval_zero") ||
                        splited_command[i].startsWith("con_req_crc_zero") ||
                        splited_command[i].startsWith("con_req_length_zero") ||
                        splited_command[i].startsWith("con_req_channel_map_zero") ||
                        splited_command[i].startsWith("con_req_timeout_zero") ||
                        splited_command[i].startsWith("con_req_hop_zero") ||
                        splited_command[i].startsWith("version_req_llid_zero") ||
                        splited_command[i].startsWith("version_req_max_len") ||
                        splited_command[i].startsWith("enc_pause_resp_plain")

                ){
                    if(!splited_result[i].startsWith("null_action") && !splited_result[i].startsWith("security_mode_reject") && !splited_result[i].startsWith("auth_failure_seq") && !splited_result[i].startsWith("rrc_connection_reest_req")){
                        bw1.append(entry + '\n');
                    }
                }
            }

        } catch (Exception e){
            System.err.println("ERROR: Could not update learning log");

        }
        String id = "";
        try{
            String command = entry.split("/")[0].split("\\[")[1];
            String result = entry.split("/")[1].split("]")[0];
            command = String.join(" ", command.split("\\s+"));
            result = String.join(" ", result.split("\\s+"));
            String query = " insert into queryNew_" +config.db_table_name+" (id, command, resultHash, result, prefLen)"
                    + " values (?, ?, ? ,?, ?)";
            command = command.replaceAll("\\|"," ");
            result = result.replaceAll("\\|"," ");
            result = result.replaceAll("attach_request_guti","attach_request");
            result = result.replaceAll("EXCEPTION","null_action");
            System.out.println("OUTPUT: "+ command+" / "+result);

            PreparedStatement preparedStmt = myConn.prepareStatement(query);
            String commandPlusLen = command+prefLen;
            preparedStmt.setString(1, getMD5(commandPlusLen));
            id = getMD5(commandPlusLen);
            preparedStmt.setString(2, command);
            preparedStmt.setString(3, getMD5(result));
            preparedStmt.setString(4, result);
            preparedStmt.setInt(5,prefLen);
            preparedStmt.execute();
//            myConn.close();
            //preparedStmt.close();
            System.out.println("Added to DB! in Resumer");
        }catch (SQLException e) {
//            System.out.println("Exception: " + e.getMessage());
            System.out.println("history already exist in Add_Entry in QueryNew (Learning Resumer)!!");
//            e.printStackTrace();
//            this.delete_Entry(id);
//            System.out.println("Deleted. Trying again...");
//            this.add_Entry(entry, prefLen);
        }catch(Exception e){
            System.out.println("DB add_Entry Error!");
             //e.printStackTrace();
        }
//        System.out.println("GOT OUT OF TRY CATCH: IN LEARNING_RESUMER 365");
    }

//    public void delete_Entry(String id){
//        Connection myConn = this.getResumerConnection();
//        if (myConn == null){
//            System.out.println("***** IN Learning_Resumer.delete_Entry(): RESUMER CONNECTION NULL *****");
//        }
//        try{
//            if(myConn != null) {
//
//                String query = " delete from queryNew_" +config.db_table_name+" where id = ?";
//                PreparedStatement preparedStmt = myConn.prepareStatement(query);
//                preparedStmt.setString(1, id);
//                preparedStmt.execute();
//                preparedStmt.close();
//            }
//        }catch(Exception e){
//            System.out.println("DB delete Error!");
//            e.printStackTrace();
//        }
//
//    }

}
