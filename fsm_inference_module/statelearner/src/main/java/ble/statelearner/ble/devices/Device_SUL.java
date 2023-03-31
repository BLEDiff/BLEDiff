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

import ble.statelearner.ble.BLESUL;
import ble.statelearner.StateLearnerSUL;
import ble.statelearner.SlaveAddressFinder;


public abstract class Device_SUL{
    BLESUL blesul;
    String state_machine;

    public Device_SUL(BLESUL blesul, String state_machine) {
        this.blesul = blesul;
        this.state_machine = state_machine;
    }

    public abstract void pre();
    public abstract void post();
    public abstract String step(String symbol);
}