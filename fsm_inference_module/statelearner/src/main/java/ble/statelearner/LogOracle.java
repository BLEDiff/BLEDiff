package ble.statelearner;

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

import de.learnlib.api.MembershipOracle;
import de.learnlib.api.MembershipOracle.MealyMembershipOracle;
import de.learnlib.api.Query;
import de.learnlib.logging.LearnLogger;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;

import javax.annotation.ParametersAreNonnullByDefault;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.System.exit;

// Based on SULOracle from LearnLib by Falk Howar and Malte Isberner
@ParametersAreNonnullByDefault
public class LogOracle<I, D> implements MealyMembershipOracle<I,D> {
	public static boolean sul_post_value = false;
	public static class MealyLogOracle<I,O> extends LogOracle<I,O> {
		public MealyLogOracle(StateLearnerSUL<I, O> sul, LearnLogger logger, boolean combine_query) {
			super(sul, logger, combine_query);

		}
	}
	
	LearnLogger logger;
	StateLearnerSUL<I, D> sul;
	boolean combine_query = false;
	LearningConfig config = null;
	Learning_Resumer learning_resumer = null;
	Cache cache = null;

	private final String[] expectedResults = {"scan_resp" ,
			"null_action",
			"DONE"};

    public LogOracle(StateLearnerSUL<I, D> sul, LearnLogger logger, boolean combine_query) {
		try {
			this.sul = sul;
			this.logger = logger;
			this.combine_query = combine_query;
			File f1 = new File("src/unresponsive.log");
			if (f1.createNewFile()) {
				System.out.println("unresponsive.log file has been created.");
			}
			try {
				this.config = new LearningConfig("src/ble.properties");
			} catch (IOException e) {
				e.printStackTrace();
			}

			if (config.resume_learning_active) {

				System.out.println("Loading Learning Resumer");
				learning_resumer = new Learning_Resumer(config.path_to_resuming_log, config.path_to_plain_replay);
			}

			if (config.cache_active) {
				System.out.println("Initializing Cache");
				cache = new Cache(config.path_to_cache_log);
			}
		}catch (Exception e){
			e.printStackTrace();
		}

	}
    
    public Word<D> answerQueryCombined(Word<I> prefix, Word<I> suffix) {
		Word<I> query = prefix.concat(suffix);
		Word<D> response = null;
		Word<D> responsePrefix = null;
		Word<D> responseSuffix = null;

		try {

			this.sul.pre();
			response = this.sul.stepWord(query);
			responsePrefix = response.subWord(0, prefix.length());
			responseSuffix = response.subWord(prefix.length(), response.length());

			logger.logQuery("INFO: [" + prefix.toString() + " | " + suffix.toString() + " / " + responsePrefix.toString() + " | " + responseSuffix.toString() + "]");
		} finally {
			//sul.post();
		}

		// Only return the responses to the suffix
		return responseSuffix;
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
		//System.out.println("Getting closest of " + result);

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

	public Word<D> answerQuerySteps (Word<I> prefix, Word<I> suffix) {
    	System.out.println("Query processing: ");

    	String first = "";
    	try {
			System.out.println("[" + prefix.toString() + " | " + suffix.toString() + "]");
		} catch (Exception e) {

		}


    	List<Word<D>> responseWordList = new ArrayList<>();
    	List<Word<D>> prefixToStringList = new ArrayList<>();
    	List<String> responseToStringList = new ArrayList<>();
    	int prefLen = prefix.length();
    	if(prefix.toString().contains("\u03B5")){
    		prefLen+=1;
		}
    	Boolean resumed = false;
    	int num_of_repeated_queries = 1;

    	// Attempt to look up in resume learner prior to executing the query
    	if (config.resume_learning_active) {
    		// Prepares the Prefix and Suffix to look up in the map, mapping queries and corresponding result
    		WordBuilder<D> wbPrefix = new WordBuilder<>(prefix.length());
    		WordBuilder<D> wbSuffix = new WordBuilder<>(suffix.length());

			String query = prefix.toString() + "|" + suffix.toString();
			//System.out.println("QUERY: " + query);
			String response = learning_resumer.query_resumer(query, prefLen);

			// Query was found in the query resumer
			// Resume becomes true when it is found in the map and correctly loads the corresponding result
			if (response != null) {
				System.out.println("Found in previous log. Response = " + response);

				String[] str_prefix;
				String[] str_suffix;

				try {
					str_prefix = response.split("\\|")[0].split(" ");
					str_suffix = response.split("\\|")[1].split(" ");

					int ctr = 0;
					for (I sym : prefix) {
						wbPrefix.add((D) str_prefix[ctr]);
						ctr++;
					}

					ctr = 0;

					for (I sym : suffix) {
						wbSuffix.add((D) str_suffix[ctr]);
						ctr++;
					}

					//System.out.println("Loaded from query: "+response);
					//logger.logQuery("[" + prefix.toString() + " | " + suffix.toString() + " / " + wbPrefix.toWord().toString() + " | " + wbSuffix.toWord().toString() + "]");

					responseWordList.add(wbSuffix.toWord());
					responseToStringList.add(wbSuffix.toWord().toString());
					prefixToStringList.add(wbPrefix.toWord());
					resumed = true;
				} catch (Exception e) {
					System.out.println("ERROR: Incorrect resume log, skipping");
					e.printStackTrace();
					resumed = false;
				}
			}



    	}

		// Only executes when the query has not been previously explored
		// ,an error occurred while loading the result from the resumer
		// or resumer is inactive
		if (!resumed || !config.resume_learning_active) {
			// If the resumer is active then display a message to let
			// the user know the query was not found in the log file
			if (config.resume_learning_active)
				System.out.println("Not found in previous log");

			// If the cache is active, we must execute the same query
			// three times to avoid inconsistency

			int extraRounds = 0;
			int prefix_len_flag = 0;
			if (config.cache_active)
				num_of_repeated_queries = 1;

			int consistent_counter;

			for (int i = 0; i < num_of_repeated_queries ; i++) {
				Boolean time_out_occured_in_enable_s1 = false;

				WordBuilder<D> wbTempPrefix;
				WordBuilder<D> wbTempSuffix;

				String current_query;
				String current_result;
				String current_query_suffix;
				String current_result_suffix;

				Boolean consistent;
				consistent_counter = 0;
				do{
					wbTempPrefix = new WordBuilder<>(prefix.length());
					wbTempSuffix = new WordBuilder<>(suffix.length());
					consistent = true;
					// Invokes reset commands
					this.sul.pre();
					current_query = "";
					current_result = "";
					current_query_suffix = "";
					current_result_suffix = "";

					try {
						for (I sym : prefix) {
							if(!consistent)
								break;

							String message = (String) sym;
							current_query += " " + sym;
							current_query = current_query.trim();
							//System.out.println("Current Query = " + current_query);
							// If a timeout occured in enable_s1
							// then all future actions
							// are marked as null action
//							if (time_out_occured_in_enable_s1) {
//								System.out.println("NULL ACTION from previous enable_s1 time out");
//								wbTempPrefix.add((D) "null_action");
//
//								current_result += " null_action";
//								current_result.trim();
//
//								continue;
//							}

							String result = (String) this.sul.step(sym);

							// Levenshtein Distance to make up for
							// missing bytes during transmission of result

							if (result.matches("timeout")) {
								result = "null_action";
							}

							wbTempPrefix.add((D) result);

							current_result += " " + result;
							current_result = current_result.trim();
							//System.out.println("Current Query IK= " + current_query);
							String[] split = current_query.split("\\s+");
							prefix_len_flag = split.length;
							first = split[0];
							//System.out.println("Prefix length " + prefix_len_flag + " first: "+first);

							if (config.cache_active) {
								// Looks up the current on going query to detect early inconsistency
								//System.out.println("Cache active!");
								String result_in_cache = cache.query_cache(current_query);
								//System.out.println("Current Query: " + current_query);
								//System.out.println("Obtained Result: " + current_result);
								//System.out.println("Execpted Result: " + result_in_cache);
								// If branch that is only executed when an inconsistency has been found
								if (result_in_cache != null && !current_result.matches(result_in_cache)) {
									//System.out.println("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
									System.out.println("Inconsistency in prefix, retrying from beginning");
									System.out.println("Current Query: " + current_query);
									System.out.println("Obtained Result: " + current_result);
									System.out.println("Execpted Result: " + result_in_cache);
									consistent = false;
									extraRounds = 2;
									try(FileWriter fw = new FileWriter("Inconsistent Query.txt", true);
										BufferedWriter bw = new BufferedWriter(fw);
										PrintWriter out = new PrintWriter(bw))
									{
										out.println("Current Query: "+ current_query+"\n"+"Current Result:"+current_result+"\n"+"Result in Cache:"+result_in_cache+"\n");
									} catch (IOException e) {
										System.out.println("File not found!");
									}
									consistent_counter++;
									System.out.println("!!!!!!!!! Consistent counter = " + consistent_counter+ " !!!!!!!!!!!");
									//incresaedcount = 2;
								}
							}
						}

						// Suffix: Execute symbols, outputs constitute output word
						for (I sym : suffix) {
							String message = (String) sym;
							if (!consistent)
								break;

							if (time_out_occured_in_enable_s1) {
								System.out.println("NULL_ACTION from previous enable_s1 timeout");
								wbTempSuffix.add((D) "null_action");
								continue;
							}
							String message_suffix = (String) sym;
							current_query_suffix += " " + sym;
							current_query_suffix = current_query_suffix.trim();



							String result = (String) this.sul.step(sym);

							// Levensthein Distance to make up for
							// missing bytes during transmission of result
							//result = getClosests(result);

							if (result.matches("timeout") && message.matches("enable_s1")) {
								System.out.println("Time out from SUL step in enable_s1");
								time_out_occured_in_enable_s1 = true;
								result = "null_action";
							}

							wbTempSuffix.add((D) result);
							current_result_suffix += " " + result;
							current_result_suffix = current_result_suffix.trim();
							//System.out.println("Current Query IK= " + current_query_suffix);
							String[] split = current_query_suffix.split("\\s+");
							System.out.println("Current Query: " + prefix.toString());

							if (config.cache_active & prefix.toString().equals("ε") & !first.equals("feature_req")) {
								// Looks up the current on going query to detect early inconsistency
								System.out.println("Cache active! for suffix!");
								String result_in_cache = cache.query_cache(current_query_suffix);
								System.out.println("Current Query Suffix: " + current_query_suffix);
								System.out.println("Obtained Result Suffix: " + current_result_suffix);
								System.out.println("Execpted Result Suffix: " + result_in_cache);
								// If branch that is only executed when an inconsistency has been found
								if (result_in_cache != null && !current_result_suffix.matches(result_in_cache)) {
									//System.out.println("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
									System.out.println("Inconsistency in suffix, retrying from beginning");
									System.out.println("Current Query Suffix: " + current_query_suffix);
									System.out.println("Obtained Result Suffix: " + current_result_suffix);
									System.out.println("Execpted Result Suffix: " + result_in_cache);
									consistent = false;
									extraRounds = 2;
									try(FileWriter fw = new FileWriter("Inconsistent Query.txt", true);
										BufferedWriter bw = new BufferedWriter(fw);
										PrintWriter out = new PrintWriter(bw))
									{
										out.println("Current Query: " + "[" + prefix.toString() + " | " + suffix.toString() + " / " + wbTempPrefix.toWord().toString() + " | " + wbTempSuffix.toWord().toString() + "]" +
												"\n"+"Current Query Sufix: " + current_query_suffix +
												"\n"+"Current Result:" + current_result_suffix +
												"\n"+"Result in Cache:"+result_in_cache+"\n");
									} catch (IOException e) {
										System.out.println("File not found!");
									}
									consistent_counter++;
									System.out.println("!!!!!!!!! Consistent counter Suffix = " + consistent_counter+ " !!!!!!!!!!!");
									//incresaedcount = 2;
								}
							}
							System.out.println("QUERY # " + (i + 1) + " / 3");
							System.out.println("[" + prefix.toString() + " | " + suffix.toString() + " / " + wbTempPrefix.toWord().toString() + " | " + wbTempSuffix.toWord().toString() + "]");
						}
					} finally {
						if(resumed == false) {
							String output = "";
							//WordBuilder<I> postfix = new WordBuilder<I>(1);
							//String s = "post_query_check";
							//postfix.append(((I) s));
							//System.out.println("Going to LTUESUL for Post Query Checking!");
							//for (I sym : postfix) {
								//System.out.println(sym.toString());
								//output = (String) this.sul.step(sym);
							//}
							//if (output.contains("false")) {
								//i--;
								//System.out.println("#################Something died skipping this step#################");
								//continue;
							//}
						}

						sul.post();
						if(sul_post_value){
							try (BufferedWriter bw1 = new BufferedWriter(new FileWriter("src/unresponsive.log", true))) {
								String s = "INFO: [" + prefix.toString() + " | " + suffix.toString() + " / " + wbTempPrefix.toWord().toString() + " | " + wbTempSuffix.toWord().toString() + "]"+"\n";
								bw1.append(s);
								sul_post_value = false;
							} catch (Exception e) {
								System.err.println("ERROR: Could not update inconsistent log");

							}
						}
					}

				} while(!consistent);

				prefixToStringList.add(wbTempPrefix.toWord());
				responseWordList.add(wbTempSuffix.toWord());
				responseToStringList.add(wbTempSuffix.toWord().toString());
				if(responseToStringList.size() == 2) {
					if (!responseToStringList.get(0).equals(responseToStringList.get(1))) {
						System.out.println("Found Inconsistency in 2 run Queries!!");
						num_of_repeated_queries = 3;
						continue;

					}
				}
			}
		}

		// Obtains the most common answer
		String mostRepeatedResponse = responseToStringList.stream()
				.collect(Collectors.groupingBy(w -> w, Collectors.counting()))
				.entrySet()
				.stream()
				.max(Comparator.comparing(Map.Entry::getValue))
				.get()
				.getKey();
		
		logger.logQuery("[" + prefix.toString() + " | " + suffix.toString() + " / " +
				prefixToStringList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString() + " | " +
				responseWordList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString() + "]");
		for (int i =0;i< responseWordList.size();i++){
			System.out.println("[" + prefix.toString() + " | " + suffix.toString() + " / " +
				prefixToStringList.get(i).toString() + " | " +
				responseWordList.get(i).toString() + "]");
				//System.out.println(responseToStringList.get(i));
	
		}
		//System.out.println("[" + prefix.toString() + " | " + suffix.toString() + " / " +
		//		prefixToStringList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString() + " | " +
		//		responseWordList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString() + "]");
		if(config.resume_learning_active){
			String query = prefix.toString() + "|" + suffix.toString();
			String result = prefixToStringList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString()
					+ "|" + responseWordList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString();

			learning_resumer.add_Entry("INFO: [" + query + "/" + result + "]",prefLen);
			//Terminating condition
			//if (result.contains("pair_resp") || result.contains("start_enc_resp")) {
				//exit(0);
			//}
//			System.out.println("GOT OUT OF ADD_ENTRY: IN LogOracle 487");
		}

		if(config.cache_active){
			String query = prefix.toString() + "|" + suffix.toString();
			String result = prefixToStringList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString()
					+ "|" + responseWordList.get(responseToStringList.indexOf(mostRepeatedResponse)).toString();
			//cache.add_Entry("INFO: [" + query + "/" + result + "]");
		}

//		System.out.println("GOT OUT OF IF: IN LogOracle 497");
//		System.out.println(responseWordList.get(responseToStringList.indexOf(mostRepeatedResponse)));
//		System.out.println("GOT OUT OF PRINT: IN LogOracle 499");
		return responseWordList.get(responseToStringList.indexOf(mostRepeatedResponse));
	}

    @Override
	public Word<D> answerQuery(Word<I> prefix, Word<I> suffix) {
		if(combine_query) {
			return answerQueryCombined(prefix, suffix);
		} else {
				Word<D> answer = answerQuerySteps(prefix, suffix);
//			System.out.println("GOT OUT OF answerQuerySteps: IN LogOracle 509");
//				System.out.println(temp);
			return answer;
		}
    }
    
	@Override
    @SuppressWarnings("unchecked")
	public Word<D> answerQuery(Word<I> query) {
		return answerQuery((Word<I>)Word.epsilon(), query);
    }

    @Override
    public MembershipOracle<I, Word<D>> asOracle() {
    	return this;
    }

	@Override
	public void processQueries(Collection<? extends Query<I, Word<D>>> queries) {
		for (Query<I,Word<D>> q : queries) {
				Word<D> output = answerQuery(q.getPrefix(), q.getSuffix());
//				System.out.println("GOT OUT OF answerQuery: IN LogOracle 530");
				q.answer(output);
		}
	}
}
