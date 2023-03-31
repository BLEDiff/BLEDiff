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

import de.learnlib.api.SUL;
import de.learnlib.api.SULException;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;

import javax.annotation.Nullable;

public interface StateLearnerSUL<I, O> extends SUL<I, O> {
	default Word<O> stepWord(@Nullable Word<I> in) throws SULException {
		WordBuilder<O> wbOutput = new WordBuilder<>(in.length());
		
		for(I sym: in) {
			wbOutput.add(step(sym));
		}
		
		return wbOutput.toWord();
	}
}
