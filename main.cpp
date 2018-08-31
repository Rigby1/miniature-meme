/*
 * Master Thesis of O. Deniz Sengün
 * Implementation of Mental Card Games using ElGamal Encryption scheme
 *
 */

/*
 * File:   main.cpp
 * Author: Deniz
 *
 * Created on April 23, 2018, 9:22 PM
 */

#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <gmpxx.h>
#include <algorithm>
#include <thread>

#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <deque>

#include "DeckAndOperations.h"


#include <random>



using boost::asio::ip::tcp;
std::string outGoingConnectionIPAdress, outGoingConnectionPortNo;
bool readySent = false;
bool sharedPKSent = false;
bool isInitiator = false;
/*
 * 1 for correct shuffling.
 */
int operationController = 0;

class game_session :
		public boost::enable_shared_from_this<game_session>
{
private:
	typedef struct {
		uint32_t type;
		uint32_t size;
	} msgheader_t;
	typedef struct {
		msgheader_t header;
		std::string data;
	} msg_t;

	boost::asio::io_service &io_service;

	tcp::resolver client_resolver;
	tcp::socket   client_socket;
	boost::asio::deadline_timer client_connect_timer;
	std::list<msg_t> client_sendQueue, server_sendQueue;
	bool          client_connected = false;

	tcp::acceptor acceptor;
	tcp::socket server_socket;
	msg_t       server_readMsg, client_readMsg;

	DeckAndOperations *deck;

public:
	game_session(boost::asio::io_service& io_service, const tcp::endpoint& endpoint_server)
: io_service(io_service),
  client_resolver(io_service),
  client_socket(io_service),
  client_connect_timer(io_service),
  acceptor(io_service, endpoint_server),
  server_socket(io_service)
{
		deck = new DeckAndOperations;
}

	DeckAndOperations * getDeck(){
		return deck;
	}

	void server_accept() {
		cout << "server_accept --begin--" << std::endl;
		acceptor.async_accept(server_socket,
				boost::bind(&game_session::server_handle_accept, shared_from_this(),
						boost::asio::placeholders::error));
	}

	void server_handle_accept(const boost::system::error_code& error)
	{
		//		cout << "server_handle_accept --begin--" << std::endl;
		if (error) {
			server_accept();
		} else {
			cout << "game_session_left handle_accept -- no error --" << std::endl;
			server_read_message();
		}
	}

	void server_enqueueMessage(const std::string &s , uint32_t type) {
		size_t qs = server_sendQueue.size();
		msg_t msg;
		msg.data = s;
		msg.header.size = msg.data.size();
		msg.header.type = type;

		server_sendQueue.push_back(msg);

		if (qs == 0) {
			server_startSending();
		}
	}


	void server_startSending() {
		if (server_sendQueue.size() > 0) {
			msg_t &msg = server_sendQueue.front();

			boost::asio::async_write(server_socket,
					boost::asio::buffer(&msg.header, sizeof(msg.header)),
					boost::bind(&game_session::server_handle_sendHead, shared_from_this(),
							boost::asio::placeholders::error));
		}
	}

	void server_handle_sendHead(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: sendHead" << std::endl;
		} else {
			msg_t &msg = server_sendQueue.front();

			boost::asio::async_write(server_socket,
					boost::asio::buffer(msg.data),
					boost::bind(&game_session::server_handle_sendMsg, shared_from_this(),
							boost::asio::placeholders::error));
		}
	}
	void server_handle_sendMsg(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: sendMsg" << std::endl;
		} else {

			//			cout << "Sent Message!" << std::endl;
			server_sendQueue.pop_front();
			server_startSending();

			//			  thr.join();
		}
	}

	void server_read_message() {

		boost::asio::async_read(server_socket,
				boost::asio::buffer(&server_readMsg.header, sizeof(server_readMsg.header)),
				boost::bind(&game_session::server_handle_readHead, shared_from_this(),
						boost::asio::placeholders::error));
	}

	void server_handle_readHead(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: readHead" << std::endl;
		} else {
			server_readMsg.data.assign(server_readMsg.header.size, '\0');
			boost::asio::async_read(server_socket,
					boost::asio::buffer(server_readMsg.data),
					boost::bind(&game_session::server_handle_readMsg, shared_from_this(),
							boost::asio::placeholders::error));
		}
	}
	string c1 = "1";
	string c2 = "2";
	vector<CipherText> cDoublePrime_verifier,c_prover, c_verifier, cPrime_prover, cDoublePrime_prover, cPrime_Verifier;
	vector<size_t> recievedPiPrimeVector, recievedPiDoublePrimeVector;
	PermutationClass * piPrime_Prover;
	PermutationClass * pi_Prover;
	CipherText firstMessageCone, secondMessageCtwo, ProverCThree;
	mpz_class randomS, mDoublePrimeProver , mPrimeProver, rTriplePrimeProver, mDoublePrimeVerifier,mPrimeVerifier;
	mpz_class aOne, aTwo, aThree, aFour, r_for_correct_decryption;
	vector<mpz_class>  rVectorForOthers, r_prover ,rPrime_Prover, receivedRPrimeVector, RDouble_Verifier;
	void server_handle_readMsg(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: readMsg" << std::endl;
		} else {

			if(server_readMsg.header.type == 2) {
				if(readySent == false){
					readySent = true;
					deliver_to_Server("ready" , 2);
				}
				else {// this is else is for the one who creates deck and pk
					try	{

						if(operationController == 3) {
							deliver_to_Server(deck->pk.p.get_str(10),510);
							deliver_to_Server(deck->pk.g.get_str(10),511);
							deliver_to_Server(deck->getEncryptedSecret().get_str(10),512);
							cout << "--------- x ---------------"<< std::endl;
							cout << deck->getSecretKey() << std::endl;
							cout << "--------- g^x ---------------"<< std::endl;
							cout << deck->getEncryptedSecret() << std::endl;
							deck->generateCardsAndPutIntoDeck();
							CipherText cOne = deck->deckVector.at(0);
							CipherText cTwo = deck->deckVector.at(0);

							cOne = deck->mask_elGamal(deck->pk,cOne,NULL);

							mpz_class rPrime = deck->secretRandomR(deck->pk.p);
							cout << "--------- r' ---------------"<< std::endl;
							cout << rPrime << std::endl;



							cTwo =  deck->mask_elGamal(deck->pk,cTwo,&rPrime);
							cout << "--------- m1 and m2 ---------------"<< std::endl;

							cout << cOne << std::endl;
							cout << cTwo << std::endl;
							deliver_to_Server(cOne.c_1.get_str(10),501);
							deliver_to_Server(cOne.c_2.get_str(10),502);
							deliver_to_Server(cTwo.c_1.get_str(10),503);
							deliver_to_Server(cTwo.c_2.get_str(10),504);
						}
						else if(operationController == 4) {
							DeckAndOperations * deck = new DeckAndOperations;
							deck->generateCardsAndPutIntoDeck();
							deliver_to_Server(deck->pk.p.get_str(10),600);
							deliver_to_Server(deck->pk.g.get_str(10),601);

							CipherText cTOne, cTTwo;
							cTOne = deck->deckVector.at(0);
							cTOne = deck->mask_elGamal_with_Secret_Key(deck->pk, cTOne, NULL);
							aOne = cTOne.c_1;
							mpz_powm(aTwo.get_mpz_t(),aOne.get_mpz_t(),deck->getSecretKey().get_mpz_t(),deck->pk.p.get_mpz_t());
							cout << "---------------a1 a2 and xA-------------"<< std::endl;
							cout << aOne <<std::endl;
							cout << aTwo <<std::endl;
							cout << deck->getSecretKey() <<std::endl;
							cout << "---------------sending a1 and a2 to Verifier-------------"<< std::endl;
							cout << "---------------Size of a1:" << (aOne.get_str(10)).length() << std::endl;
							cout << "---------------Size of a2:" << (aTwo.get_str(10)).length() << std::endl;
							deliver_to_Server(aOne.get_str(10),602);
							deliver_to_Server(aTwo.get_str(10),603);
						}
						else {
							deliver_to_Server(deck->pk.p.get_str(10),101);
							deliver_to_Server(deck->pk.g.get_str(10),102);
							deliver_to_Server(deck->getEncryptedSecret().get_str(10),100);
						}
						sleep(1);

					}
					catch (std::exception& e)
					{
						std::cerr << "Exception: " << e.what() << "\n";
					}
				}
			}
			else if(server_readMsg.header.type == 101){
				deck->pk.p= server_readMsg.data;
				cout << "p is : " << deck->pk.p << std::endl;
				if(!isInitiator){
					deliver_to_Server(deck->pk.p.get_str(10),101);
				}
			}
			else if(server_readMsg.header.type == 102){
				deck->pk.g= server_readMsg.data;
				cout << "g is : " << deck->pk.g << std::endl;
				if(!isInitiator){
					deliver_to_Server(deck->pk.g.get_str(10),102);
				}
			}
			else if(server_readMsg.header.type == 100){
				if(isInitiator){
					if(!sharedPKSent){
						deck->Shared_Public_Key = server_readMsg.data;
						sharedPKSent = true;
						deliver_to_Server(deck->Shared_Public_Key.get_str(10),100);
						cout << "PUBLIC SECRET KEY IS : " << deck->Shared_Public_Key << std::endl;
					}
					else {
						string tempRecievedMessage;
						tempRecievedMessage = server_readMsg.data;
						mpz_class tempMpzClassForReceivedMessage (tempRecievedMessage);
						if(tempMpzClassForReceivedMessage == deck->Shared_Public_Key) {
							deck->generateCardsAndPutIntoDeck();
						}
						else {
							cout << "ERROR: SOMEONE IS CHEATING ON CALCULATION OF SHARED PUBLIC KEY" << std::endl;
						}

						//AFTER SHARED PUBLIC KEY IS SAME FOR ALL NODES THEN WE CONTINUE TO NEXT OPERATION


						//we need to send permutated(shuffled) deck to others in order them to shuffle as well
						cout << "--------------- 0 DeckVector After Generation  -------------" << std::endl;
						for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
							cout << *i << std::endl;
						}
						//--------------------------NEXT PHASE FROM INITIATOR DECIDED HERE -----------------
						switch(operationController) {
						case 1:
						{
							vector<size_t> permutationVector;
							deck->permutationClass = new PermutationClass(deck->deckVector.size(),true);
							deck->permutationShuffle(deck->deckVector, deck->permutationClass->map);
							//						rVectorForInitiatior = deck->generateSecretRandomRVector(deck->pk.p,deck->deckVector.size());
							//						vector<CipherText> cts= deck->re_mask_elGamal_deck(deck->pk, deck->deckVector, rVectorForInitiatior);// we use re_mask_elGamal_deck instead of mask_elGamal_deck() because
							cout << "--------------- 0.1 DeckVector After SHUFFLE  -------------" << std::endl;
							for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
								cout << *i << std::endl;
							}

							// we want to use r later for calculating r'' in zero knowledge interactive proof part
							for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
								//							cout << "Sending c1: " << i->c_1 << "\nSending c2: " << i->c_2 << std::endl;
								deliver_to_Server(i->c_1.get_str(10),201);
								deliver_to_Server(i->c_2.get_str(10),202);
							}
							deliver_to_Server("done sending",203);
							cout << "--------------- 1 - SHUFFLED DECK SENT  -------------" << std::endl;
							break;
						}
						case 2:
						{

							c_prover = deck->deckVector;
							cout << "--------------- 0.1- C Content  -------------" << std::endl;
							for(auto i = c_prover.begin(); i != c_prover.end(); i++){
								cout << *i << std::endl;
							}

							// we want to use r later for calculating r'' in zero knowledge interactive proof part
							//sendin c''

							pi_Prover = new PermutationClass(deck->deckVector.size());
							cDoublePrime_prover = c_prover;
							deck->permutationShuffle(cDoublePrime_prover, pi_Prover->map);

							r_prover = deck->generateSecretRandomRVector(deck->pk.p, cDoublePrime_prover.size());
							deck->re_mask_elGamal_deck(deck->pk,cDoublePrime_prover, r_prover);

							for(auto i = cDoublePrime_prover.begin(); i != cDoublePrime_prover.end(); i++){
								deliver_to_Server(i->c_1.get_str(10),401);
								deliver_to_Server(i->c_2.get_str(10),402);
							}
							deliver_to_Server("done sending",403);
							cout << "--------------- 1 - c'' SENT  -------------" << std::endl;
							break;
						}
						}
					}
				}else{
					if(!sharedPKSent){
						deck->generateSecretKey(&deck->pk);		//since we set public key by sending p and g we find a new secret key as we get x tilda generation
						mpz_class input(server_readMsg.data);
						sharedPKSent = true;
						deliver_to_Server(deck->contributeToSharedSecret(input).get_str(10),100);
					}
					else {
						deck->Shared_Public_Key = server_readMsg.data;
						cout << "SHARED PUBLIC KEY IS : " << deck->Shared_Public_Key << std::endl;
						deliver_to_Server(deck->Shared_Public_Key.get_str(10),100);
					}
				}

			}
			else if(server_readMsg.header.type == 510){
				deck->pk.p = server_readMsg.data;
			}
			else if(server_readMsg.header.type == 511){
				deck->pk.g = server_readMsg.data;
			}
			else if(server_readMsg.header.type == 512){
				deck->Shared_Public_Key = server_readMsg.data;
				cout << "--------- g^x ---------------"<< std::endl;
				cout << deck->Shared_Public_Key << std::endl;

			}

			else if(server_readMsg.header.type == 501){
				c1 = server_readMsg.data;

			}
			else if(server_readMsg.header.type == 502){
				c2 = server_readMsg.data;
				mpz_class aOne(c1);
				mpz_class bOne(c2);
				CipherText ct(aOne,bOne);
				firstMessageCone = ct;
			}
			else if(server_readMsg.header.type == 503){
				c1 = server_readMsg.data;

			}
			else if(server_readMsg.header.type == 504){
				c2 = server_readMsg.data;
				mpz_class aTwo(c1);
				mpz_class bTwo(c2);
				CipherText ct(aTwo,bTwo);
				secondMessageCtwo = ct;

				rTriplePrimeProver = deck->secretRandomR(deck->pk.p);

				mpz_powm(mDoublePrimeVerifier.get_mpz_t(),deck->pk.g.get_mpz_t(),rTriplePrimeProver.get_mpz_t(),deck->pk.p.get_mpz_t());

				mpz_class rDoublePrime = deck->secretRandomR(deck->pk.p);

				mpz_class g_to_rDoublePrime;
				mpz_powm(g_to_rDoublePrime.get_mpz_t(),deck->pk.g.get_mpz_t(),rDoublePrime.get_mpz_t(),deck->pk.p.get_mpz_t());
				mpz_class g_to_rDoublePrimeandSharedPublicKey;
				mpz_powm(g_to_rDoublePrimeandSharedPublicKey.get_mpz_t(),deck->Shared_Public_Key.get_mpz_t(),rDoublePrime.get_mpz_t(),deck->pk.p.get_mpz_t());

				CipherText thirdMessageCThree((g_to_rDoublePrime * firstMessageCone.c_1 / secondMessageCtwo.c_1) % deck->pk.p, (mDoublePrimeVerifier * firstMessageCone.c_2 * g_to_rDoublePrimeandSharedPublicKey / secondMessageCtwo.c_2 ) % deck->pk.p);
				cout << "a3,b3  " << thirdMessageCThree << std::endl;

				deliver_to_Server(thirdMessageCThree.c_1.get_str(10),505);
				deliver_to_Server(thirdMessageCThree.c_2.get_str(10),506);

			}

			else if(server_readMsg.header.type == 505){
				c1 = server_readMsg.data;

			}
			else if(server_readMsg.header.type == 506){
				c2 = server_readMsg.data;
				mpz_class aThree(c1);
				mpz_class bThree(c2);
				CipherText ct(aThree,bThree);
				ProverCThree = ct;

				mpz_class aThree_ToXInverse;
				mpz_powm(aThree_ToXInverse.get_mpz_t(), ProverCThree.c_1.get_mpz_t(), deck->getSecretKey().get_mpz_t(),deck->pk.p.get_mpz_t());
				mpz_invert(aThree_ToXInverse.get_mpz_t(), aThree_ToXInverse.get_mpz_t(),deck->pk.p.get_mpz_t());

				mPrimeProver = (ProverCThree.c_2 *aThree_ToXInverse)% deck->pk.p ;
				deliver_to_Server(mPrimeProver.get_str(10),507);

			}


			else if(server_readMsg.header.type == 507){
				mPrimeVerifier = server_readMsg.data;
				cout << "--------check if mPrime = mDoublePrime ----------" <<std::endl;
				cout << "mPrime is ;" << std::endl;
				cout << mPrimeVerifier << std::endl;
				cout << "MDoublePrime is ;" << std::endl;
				cout << mDoublePrimeVerifier << std::endl;

				deliver_to_Server(rTriplePrimeProver.get_str(10),508);
			}

			else if(server_readMsg.header.type == 508){
				rTriplePrimeProver = server_readMsg.data;

				mpz_class g_to_r_TriplePrime;
				mpz_powm(g_to_r_TriplePrime.get_mpz_t(),deck->pk.g.get_mpz_t(),rTriplePrimeProver.get_mpz_t(),deck->pk.p.get_mpz_t());
				cout << " ----------- g^r''' --------" << std::endl;
				cout << g_to_r_TriplePrime << std::endl;
				cout << " ----------- m' --------" << std::endl;
				cout << mPrimeProver << std::endl;
			}

			else if(server_readMsg.header.type == 201){
				c1 = server_readMsg.data;

			}
			else if(server_readMsg.header.type == 202){
				c2 = server_readMsg.data;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				cDoublePrime_verifier.push_back(ct);
			}
			else if(server_readMsg.header.type == 203){
				deck->deckVector = cDoublePrime_verifier;
				cDoublePrime_verifier.clear();
				if(!isInitiator){
					cout << "--------------- 2 - SHUFFLED DECK received  -------------" << std::endl;

					deck->permutationClass = new PermutationClass(deck->deckVector.size(),true);
					deck->permutationShuffle(deck->deckVector,deck->permutationClass->map); // nodes permutate as well
					//					rVectorForOthers = deck->generateSecretRandomRVector(deck->pk.p,deck->deckVector.size());
					//					vector<CipherText> cts= deck->re_mask_elGamal_deck(deck->pk, deck->deckVector, rVectorForOthers); // we use re_mask_elGamal_deck instead of mask_elGamal_deck() because
					// we want to use r later for calculating r'' in zero knowledge interactive proof part
					cout << "--------------- 3 - DeckVector After Re-SHUFFLE  -------------" << std::endl;
					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
						cout << *i << std::endl;
						deliver_to_Server(i->c_1.get_str(10),201);
						deliver_to_Server(i->c_2.get_str(10),202);
					}
					deliver_to_Server("done sending",203);
				}
				else {
					cout << "------------ 4 - Received ReShuffled Vector------------" << std::endl;
					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
						cout << *i << std::endl;
						deliver_to_Server(i->c_1.get_str(10),204);
						deliver_to_Server(i->c_2.get_str(10),205);
					}
					cout << "------------5- sending ReShuffled Vector to Syncronize------------" << std::endl;

					//SENDING RESHUFFLED DECK TO SYNCRONIZE WITH OTHERS
					deliver_to_Server("Masked Deck Vectors should be all same", 206);
					// now we have player times masked and permutated deckvector in maskedDeckVector as a leader
				}

			}
			else if(server_readMsg.header.type == 204){
				c1 = server_readMsg.data;
			}
			else if(server_readMsg.header.type == 205){

				c2 = server_readMsg.data;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				cDoublePrime_verifier.push_back(ct);

			}
			else if(server_readMsg.header.type == 206){
				if(!isInitiator){
					deck->deckVector = cDoublePrime_verifier;
					cDoublePrime_verifier.clear();
					cout << "------------6 - syncronizing reshuffled deck------------" << std::endl;
					cout << "------------CONTENT OF RESHUFLLED DECK IN SYNCRONIZATION PHASE------------" << std::endl;

					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
						cout << *i << std::endl;
						deliver_to_Server(i->c_1.get_str(10),204);
						deliver_to_Server(i->c_2.get_str(10),205);
					}
					deliver_to_Server("Masked Deck Vectors should be all same", 206);
				}
				else {	//LEADER STARTS NEXT PHASE OF THE GAME FROM HERE

					bool shuffleCheck = true;
					cout << "------------CONTENT OF RESHUFLLED DECK IN SYNCRONIZATION PHASE------------" << std::endl;
					for(auto i = cDoublePrime_verifier.begin(), j = deck->deckVector.begin(); i!= cDoublePrime_verifier.end() && j!=  deck->deckVector.end();i++ , j++){
						cout << *i << std::endl;
						if((*j).c_1 != (*i).c_1 && (*j).c_2 != (*i).c_2) {
							shuffleCheck = false;
						}
					}

					if(shuffleCheck == false) {
						cout << "ERROR: SOMEONE IS CHEATING DURING SHUFFLING" << std::endl;
					}
					else {
						cout << "------------7 - reshuffled vectors are all same in each node------------" << std::endl;
						cDoublePrime_verifier.clear();
					}

					switch (operationController) {
					case 1 :  // UNSHUFFLE PROGRESS IS STARTED BY INITATIOR HERE

						break;
					}


				}

			}

			/*
			 * ZERO KNOWLEDGE INTERACTIVE PROOF FOR CORRECT SHUFFLING - BEGIN
			 */
			else if(server_readMsg.header.type == 401){
				c1 = server_readMsg.data;


			}
			else if(server_readMsg.header.type == 402){
				c2 = server_readMsg.data;
				//				cout << "Received c2 is : " <<  server_readMsg.data << std::endl;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				cDoublePrime_verifier.push_back(ct);
			}
			else if(server_readMsg.header.type == 403){

				deliver_to_Server("Proove it",410);
			}


			else if(server_readMsg.header.type == 410){
				piPrime_Prover = new PermutationClass(deck->deckVector.size()); //this is pi'
				cout << "pi prime is: " << std::endl;
				for(auto i = piPrime_Prover->map.begin() ; i != piPrime_Prover->map.end(); i++) {
					cout << *i << "  ";
				}
				cout << std::endl;
				rPrime_Prover = deck->generateSecretRandomRVector(deck->pk.p,deck->deckVector.size()); //this is r prime
				cout << "rPrimeVector is: " << std::endl;

				for(auto i = rPrime_Prover.begin() ; i != rPrime_Prover.end(); i++) {
					cout << *i << "  " << std::endl;
				}

				cPrime_prover = c_prover;
				deck->permutationShuffle(cPrime_prover,piPrime_Prover->map);
				deck->re_mask_elGamal_deck(deck->pk,cPrime_prover,rPrime_Prover);
				cout << "------ Content of C' is " << std::endl;

				for(auto i = cPrime_prover.begin() ; i != cPrime_prover.end(); i++) {
					cout << *i << std::endl;
					deliver_to_Server(i->c_1.get_str(10),420);
					deliver_to_Server(i->c_2.get_str(10),421);

				}
				cout << "------ 1- COMMITMENT STARTS C' IS SENT------" << std::endl;

				deliver_to_Server("Sending c' completed", 422);

			}

			else if(server_readMsg.header.type == 420){
				c1 = server_readMsg.data;

			}
			else if(server_readMsg.header.type == 421){
				c2 = server_readMsg.data;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				cPrime_Verifier.push_back(ct);
			}
			else if(server_readMsg.header.type == 422){
				cout << "-----------------2 - C' recieved sending random S-----------------"<< std::endl;
				cout << "------------------------ CONTENT C' IS ---------------"<< std::endl;
				for(auto i = cPrime_Verifier.begin() ; i != cPrime_Verifier.end(); i++) {
					cout << *i << std::endl;
				}

				mpz_class randomS = deck->secretRandomR(deck->pk.p);
				randomS = randomS % 2;

				deliver_to_Server(randomS.get_str(10),404);
			}


			else if(server_readMsg.header.type == 404){
				mpz_class randomSTemp(server_readMsg.data);


				if(randomSTemp == 0) {
					//					cout << "-*-*-*-*---------- r' IS --------: "  << std::endl;
					for(auto i = rPrime_Prover.begin(); i!= rPrime_Prover.end();i++){
						cout<< (*i) << std::endl;
						deliver_to_Server((*i).get_str(10),405);
					}
					cout << "------3.A sending r' and pi'------" << std::endl;

					deliver_to_Server("Sending r' completed",415);

					for(auto i = piPrime_Prover->map.begin(); i != piPrime_Prover->map.end() ; i++) {
						mpz_class fromSize_tToMpz (*i);
						deliver_to_Server(fromSize_tToMpz.get_str(10),406);
					}
					deliver_to_Server("Sending pi' completed", 407);
				}
				else if (randomSTemp == 1) {

					PermutationClass piDoublePrime(cPrime_prover.size());
					piDoublePrime.map = piPrime_Prover->rmap;
					piDoublePrime.rmap = piPrime_Prover->map;
					deck->permutationShuffle(piDoublePrime.map, pi_Prover->map);

					vector<mpz_class> rDoublePrime_Prover;
					vector<mpz_class> tempRprimeCombinedWithPiDoublePrime = rPrime_Prover;
					deck->permutationShuffle(tempRprimeCombinedWithPiDoublePrime, piDoublePrime.map);
					int j = 0;
					for(auto i = r_prover.begin(); i!= r_prover.end();i++){
						rDoublePrime_Prover.push_back( (*i) - tempRprimeCombinedWithPiDoublePrime[j]);
						j++;
					}


					for(auto i = rDoublePrime_Prover.begin(); i!= rDoublePrime_Prover.end();i++){
						//						cout<< (*i) << " ";
						deliver_to_Server((*i).get_str(10),408);
					}

					for(auto i = piDoublePrime.map.begin(); i!= piDoublePrime.map.end();i++){
						mpz_class fromSize_tToMpz (*i);
						cout << "Size of a element pi' :"<< fromSize_tToMpz.get_str(10).length() << std::endl;
						deliver_to_Server(fromSize_tToMpz.get_str(10),409);
					}


					vector<CipherText> cThatMustBeEqualToCDoublePrimeInTheEnd = cPrime_prover;


					deck->permutationShuffle(cThatMustBeEqualToCDoublePrimeInTheEnd,piDoublePrime.map);
					deck->re_mask_elGamal_deck(deck->pk,cThatMustBeEqualToCDoublePrimeInTheEnd,rDoublePrime_Prover);
					cout<< "********------------------- Pi'' and R'' apllied on c' "<< std::endl;
					for(auto i = cThatMustBeEqualToCDoublePrimeInTheEnd.begin(); i!= cThatMustBeEqualToCDoublePrimeInTheEnd.end();i++){
						cout<< (*i) << std::endl;
					}

					cout<< "********------------------- c'' ---------------------- "<< std::endl;
					for(auto i = cDoublePrime_prover.begin(); i!= cDoublePrime_prover.end();i++){
						cout<< (*i) << std::endl;
					}



					cout << "------3.B sending r'' and pi''------" << std::endl;

					deliver_to_Server("Sending Completed!",440);




				}
				else {
					std::cerr << "error: " << "\n";
				}

			}

			else if(server_readMsg.header.type == 405){
				mpz_class receivedrPrime(server_readMsg.data);
				receivedRPrimeVector.push_back(receivedrPrime);
				//				std::cout << "Received r' :  " <<  server_readMsg.data << std::endl;

			}
			else if(server_readMsg.header.type == 406){
				size_t tmpSize_t = 0;
				sscanf(server_readMsg.data.c_str(),"%zu", &tmpSize_t);
				recievedPiPrimeVector.push_back(tmpSize_t);
				//				std::cout << "Received pi' :  " <<  tmpSize_t << " ";


			}
			else if(server_readMsg.header.type == 407){
				cout << "-------------------received pi' and r' -------------" << std::endl;

				cout << "-------------------4.A case 1: s=0--------------" << std::endl;
				std::cout << "Received pi' completed" << std::endl;
				deck->generateCardsAndPutIntoDeck();
				c_verifier = deck->deckVector;
				vector<CipherText> c_appliedByRprimeandPiPrime_verifier;
				c_appliedByRprimeandPiPrime_verifier = c_verifier;
				deck->permutationShuffle(c_appliedByRprimeandPiPrime_verifier,recievedPiPrimeVector);
				deck->re_mask_elGamal_deck(deck->pk,c_appliedByRprimeandPiPrime_verifier,receivedRPrimeVector);
				cout << "-------------------------COMPARISON -- content OF C' ----------------------" << std::endl;
				for(auto i = cPrime_Verifier.begin(); i!= cPrime_Verifier.end();i++){
					cout << (*i) << std::endl;
				}
				cout << "-------------------------COMPARISON -- c applied r' and pi' ----------------------" << std::endl;
				for(auto i = c_appliedByRprimeandPiPrime_verifier.begin(); i!= c_appliedByRprimeandPiPrime_verifier.end();i++){
					cout << (*i) << std::endl;
				}

				bool cheatDetected = false;
				for(auto i = cPrime_Verifier.begin(), j = c_appliedByRprimeandPiPrime_verifier.begin(); i!= cPrime_Verifier.end() && j!= c_appliedByRprimeandPiPrime_verifier.end();i++ , j++){
					if((*j).c_1 != (*i).c_1 && (*j).c_2 != (*i).c_2) {
						cheatDetected = true;
					}
				}
				if(cheatDetected){
					cout << "------ CHEAT DETECTED ------ \nCheat detected while comparing c and c'" << std::endl;
				}
				else{
					cout << "--------------- COMPARISON OF C AND C' IS OKAY - ZERO KNOWLEDGE INTERACTIVE PROOF WORKED------------" << std::endl;
					cDoublePrime_verifier.clear(); c_prover.clear(); c_verifier.clear(); cPrime_prover.clear(); cDoublePrime_prover.clear(); cPrime_Verifier.clear();
					recievedPiPrimeVector.clear(); recievedPiDoublePrimeVector.clear();

					rVectorForOthers.clear(); r_prover.clear(); rPrime_Prover.clear(); receivedRPrimeVector.clear(); RDouble_Verifier.clear();
				}



			}
			else if(server_readMsg.header.type == 408){
				mpz_class recievedRDoublePrime (server_readMsg.data);
				RDouble_Verifier.push_back(recievedRDoublePrime);
				//				std::cout << "Received r'' :  " <<  server_readMsg.data << std::endl;
			}
			else if(server_readMsg.header.type == 409){
				size_t tmpSize_t = 0;
				sscanf(server_readMsg.data.c_str(),"%zu", &tmpSize_t);
				recievedPiDoublePrimeVector.push_back(tmpSize_t);
				//				std::cout << "Received pi'' :  " <<  tmpSize_t << " ";
			}

			else if(server_readMsg.header.type == 440){
				cout << "-------------------4.B case 2: s=1--------------" << std::endl;

				//				std::cout << "Received pi'' completed" << std::endl;
				vector<CipherText> secondTempDeck = cPrime_Verifier;
				cout <<"----------------C' before remask and repermutate------------------\n";
				//				for(auto i = secondTempDeck.begin(); i != secondTempDeck.end(); i++){
				//					CipherText citext = deck->finalize_unmask_elGamal(deck->pk,*i);
				//					cout << citext << std::endl;
				//				}
				deck->permutationShuffle(secondTempDeck,recievedPiDoublePrimeVector);
				deck->re_mask_elGamal_deck(deck->pk,secondTempDeck,RDouble_Verifier);


				cout << "-------------------------COMPARISON -- content OF deck applied by pi'' and r'' ----------------------" << std::endl;
				for(auto i = secondTempDeck.begin(); i!= secondTempDeck.end();i++){
					cout << (*i) << std::endl;
				}
				cout << "-------------------------COMPARISON -- content OF C'' ----------------------" << std::endl;
				for(auto i = cDoublePrime_verifier.begin(); i!= cDoublePrime_verifier.end();i++){
					cout << (*i) << std::endl;
				}

				bool cheatDetected = false;
				for(auto i = secondTempDeck.begin(), j = cDoublePrime_verifier.begin(); i!= secondTempDeck.end() && j!=  cDoublePrime_verifier.end();i++ , j++){
					if((*j).c_1 != (*i).c_1 || (*j).c_2 != (*i).c_2) {
						cheatDetected = true;
					}
				}
				if(cheatDetected){
					cout << "------ CHEAT DETECTED ------ \nCheat detected while comparing c and c'' (CASE 2)" << std::endl;
				}
				else{
					cout << "--------------- COMPARISON OF C AND C'' IS OKAY - ZERO KNOWLEDGE INTERACTIVE PROOF WORKED------------" << std::endl;
					cDoublePrime_verifier.clear(); c_prover.clear(); c_verifier.clear(); cPrime_prover.clear(); cDoublePrime_prover.clear(); cPrime_Verifier.clear();
					recievedPiPrimeVector.clear(); recievedPiDoublePrimeVector.clear();
					rVectorForOthers.clear(); r_prover.clear(); rPrime_Prover.clear(); receivedRPrimeVector.clear(); RDouble_Verifier.clear();
				}
			}
			else if(server_readMsg.header.type == 415){
				std::cout << "Receiveing r' Completed" << std::endl;
			}

			else if(server_readMsg.header.type == 600){
				deck->pk.p = server_readMsg.data;
			}
			else if(server_readMsg.header.type == 601){
				deck->pk.g = server_readMsg.data;
			}
			else if(server_readMsg.header.type == 602){
				aOne = server_readMsg.data;
			}
			else if(server_readMsg.header.type == 603){
				aTwo = server_readMsg.data;

				mpz_class r = deck->secretRandomR(deck->pk.p);
				r_for_correct_decryption = r;

				mpz_powm(aThree.get_mpz_t(),aOne.get_mpz_t(),r.get_mpz_t(),deck->pk.p.get_mpz_t());
				cout << "------------------ a3 (a1^r)-------------"<< std::endl;
				cout << aThree << std::endl;
				cout << "------------------sending a3 to Prover-------------"<< std::endl;
				cout << "---------------Size of a3:" << (aThree.get_str(10)).length() << std::endl;

				deliver_to_Server(aThree.get_str(10),604);

			}
			else if(server_readMsg.header.type == 604){
				aThree = server_readMsg.data;

				mpz_powm(aFour.get_mpz_t(),aThree.get_mpz_t(),deck->getSecretKey().get_mpz_t(),deck->pk.p.get_mpz_t());

				cout << "------------------ a4 (a3^x)-------------"<< std::endl;
				cout << aFour << std::endl;
				cout << "------------------sending a4 to Verifier-------------"<< std::endl;
				cout << "---------------Size of a4:" << (aFour.get_str(10)).length() << std::endl;

				deliver_to_Server(aFour.get_str(10),605);

			}

			else if(server_readMsg.header.type == 605){
				aFour = server_readMsg.data;
				cout << "------------------sending r' to Prover-------------"<< std::endl;
				cout << "---------------Size of r':" << (r_for_correct_decryption.get_str(10)).length() << std::endl;
				deliver_to_Server(r_for_correct_decryption.get_str(10),606);

				cout << "------------------ Check if a4 = a2^r-------------"<< std::endl;

				mpz_class aTwoToR;
				mpz_powm(aTwoToR.get_mpz_t(),aTwo.get_mpz_t(),r_for_correct_decryption.get_mpz_t(),deck->pk.p.get_mpz_t());
				cout << "------------------ a4 -------------"<< std::endl;
				cout << aFour << std::endl;
				cout << "------------------ a2^r-------------"<< std::endl;
				cout << aTwoToR << std::endl;
				if(aTwoToR == aFour){
					cout << "---------------CORRECT DECRYPTION PROVEN--------" <<std::endl;

				}
				else {
					cout << "---------------a2^r != a4--------" <<std::endl;
					cout << "---------------CHEAT DETECTED--------" <<std::endl;
				}
			}


			else if(server_readMsg.header.type == 606){
				r_for_correct_decryption = server_readMsg.data;

				cout << "------------------ Check if a3 = a1^r-------------"<< std::endl;

				mpz_class aOneToR;
				mpz_powm(aOneToR.get_mpz_t(),aOne.get_mpz_t(),r_for_correct_decryption.get_mpz_t(),deck->pk.p.get_mpz_t());
				cout << "------------------ a3 -------------"<< std::endl;
				cout << aThree << std::endl;
				cout << "------------------ a1^r-------------"<< std::endl;
				cout << aOneToR << std::endl;
				if(aOneToR == aThree){
					cout << "---------------CORRECT DECRYPTION PROVEN--------" <<std::endl;
				}
				else {
					cout << "---------------a1^r != a3--------" <<std::endl;
					cout << "---------------CHEAT DETECTED--------" <<std::endl;
				}
			}

			/*
			 * ZERO KNOWLEDGE INTERACTIVE PROOF FOR CORRECT SHUFFLING - END
			 */
			server_read_message();
		}
	}

	void client_schedule_connect() {
		client_connect_timer.expires_from_now(boost::posix_time::milliseconds(1000));
		client_connect_timer.async_wait(boost::bind(&game_session::client_handle_connect_timer, shared_from_this()));
	}

	void client_handle_connect_timer(){
		tcp::resolver::query query(outGoingConnectionIPAdress, outGoingConnectionPortNo);
		client_resolver.async_resolve(query,
				boost::bind(&game_session::client_handle_resolve, shared_from_this(),
						boost::asio::placeholders::error,
						boost::asio::placeholders::iterator));

	}

	void client_handle_resolve(const boost::system::error_code& err,
			tcp::resolver::iterator iterator) {
		if (err) {
			//error
			cout << "error resolve " << err << std::endl;
			client_schedule_connect();
		} else {
			boost::asio::async_connect(client_socket, iterator,
					boost::bind(&game_session::client_handle_connect, shared_from_this(),
							boost::asio::placeholders::error));
		}
	}

	void client_handle_connect(const boost::system::error_code& err)
	{
		if (err) {
			cout << "error connect " << err << std::endl;
			client_schedule_connect();
		} else {
			//			cout << "game_session_left start() \n";
			client_connected = true;
			client_startSending();
		}
	}
	/*
	 * wait = 1
	 * ready = 2
	 * start = 3
	 * EncryptedPublicKey = 100
	 * p = 101
	 * g = 102
	 * send deck to shuffle c1 = 201
	 * send deck to shuffle c2 = 202
	 * whole vector was taken to shuffle = 203
	 * send masked c1 to all peers to syncronize = 204
	 * send masked c2 to  all peers to syncronize = 205
	 * whole vector was taken to shuffle = 206
	 * Completed all encrypted cards same all in each peer with same order = 206
	 * unmask and reverse shuffle operation c1 = 301
	 * unmask and reverse shuffle operation c2 = 302
	 * unmask operation finalize = 303
	 * syncronize after unshuffle c1 = 306
	 * syncronize after unshuffle c2 = 307
	 * syncronize after unshuffle finalize = 308
	 * proving correct shuffle zero knowledge interactive proof - commitment = 401
	 * proving correct shuffle zero knowledge interactive proof - sending c1 = 402
	 * proving correct shuffle zero knowledge interactive proof - sending c2 = 403
	 * proving correct shuffle zero knowledge interactive proof - sending completed = 404
	 * proving correct shuffle zero knowledge interactive proof - sending r' = 405
	 * proving correct shuffle zero knowledge interactive proof - sending r' completed = 415
	 * proving correct shuffle zero knowledge interactive proof - sending pi' = 406
	 * proving correct shuffle zero knowledge interactive proof - sending pi' completed = 407
	 * node asks for proof = 410
	 * proving correct shuffle zero knowledge interactive proof - sending r''  = 418
	 * proving correct shuffle zero knowledge interactive proof - sending r'' completed = 418
	 *
	 */
	void client_enqueueMessage(const std::string &s , uint32_t type) {
		size_t qs = client_sendQueue.size();
		msg_t msg;
		msg.data = s;
		msg.header.size = msg.data.size();
		msg.header.type = type;

		client_sendQueue.push_back(msg);

		if (qs == 0) {
			client_startSending();
		}
	}
	void client_startSending() {
		if (client_connected && client_sendQueue.size() > 0) {
			msg_t &msg = client_sendQueue.front();

			boost::asio::async_write(client_socket,
					boost::asio::buffer(&msg.header, sizeof(msg.header)),
					boost::bind(&game_session::client_handle_sendHead, shared_from_this(),
							boost::asio::placeholders::error));
		}
	}
	void client_handle_sendHead(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: sendHead" << std::endl;
		} else {
			msg_t &msg = client_sendQueue.front();
			boost::asio::async_write(client_socket,
					boost::asio::buffer(msg.data),
					boost::bind(&game_session::client_handle_sendMsg, shared_from_this(),
							boost::asio::placeholders::error));
		}
	}
	void client_handle_sendMsg(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: sendMsg" << std::endl;
		} else {

			client_sendQueue.pop_front();
			client_startSending();
		}
	}

	void deliver_to_Server(const std::string& msg, uint32_t type)
	{
		//		cout << "game_session_left deliver() \n";
		io_service.post(boost::bind(&game_session::client_enqueueMessage, shared_from_this(), msg, type));

	}

	void deliver_to_Client(const std::string& msg, uint32_t type)
	{
		//		cout << "game_session_left deliver() \n";
		io_service.post(boost::bind(&game_session::server_enqueueMessage, shared_from_this(), msg, type));

	}

	void client_read_message() {

		cout << "------ client Read Message" << std::endl;
		boost::asio::async_read(client_socket,
				boost::asio::buffer(&client_readMsg.header, sizeof(client_readMsg.header)),
				boost::bind(&game_session::client_handle_readHead, shared_from_this(),
						boost::asio::placeholders::error));
	}

	void client_handle_readHead(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: readHead" << std::endl;
		} else {
			client_readMsg.data.assign(client_readMsg.header.size, '\0');
			boost::asio::async_read(client_socket,
					boost::asio::buffer(client_readMsg.data),
					boost::bind(&game_session::client_handle_readMsg, shared_from_this(),
							boost::asio::placeholders::error));
		}
	}

	void client_handle_readMsg(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: readHead" << std::endl;
		}
		else {
			cout << " -----------------A MESSAGE TAKEN AS A CLIENT ------------" << std::endl;
			cout << client_readMsg.data;
		}


	}


};

typedef boost::shared_ptr<game_session> game_session_ptr;



boost::asio::io_service io_service;
int main(int argc, char** argv) {

	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard = boost::asio::make_work_guard(io_service);
	boost::thread t(boost::bind(&boost::asio::io_service::run, boost::ref(io_service)));

	cout << "Enter port number to open: ";
	int incomingConnection;
	cin >> incomingConnection;

	cout << "Enter IP number to connect: ";
	cin >> outGoingConnectionIPAdress;
	cout << "Enter port number to connect: ";
	cin >> outGoingConnectionPortNo;


	tcp::endpoint endpoint(tcp::v4(), incomingConnection);

	game_session_ptr new_session(new game_session(io_service, endpoint));
	new_session->server_accept();
	new_session->client_schedule_connect();


	sleep(1);

	int controllerInput = 15;
	cout<<"\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"<<endl;
	cout<<"Press appropriate key:"<<endl;
	cout<<"Press 1 to Shuffle with Multiple players."<<endl;
	cout<<"Press 2 to Prove correct masking and shuffling in between two nodes. " <<endl;
	//	cout<<"Press 3 to Prove correct Re-Encryption in between two nodes. "<<endl;
	cout<<"Press 4 to Prove correct Decryption in between two nodes. "<<endl;
	cout<<"Press 5 to Correct Masking and Shuffling internally!. "<<endl;
	cout<<"Press 6 to Shuffle then Unshuffle internally!. "<<endl;
	cout<<"Press 7 to Mask then Unmask internally!. "<<endl;
	cout<<"Press 10 to Prove correct Decryption internally!. "<<endl;



	cout<<"Press 0 to Terminate "<<endl;
	cout<<"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"<<endl;
	while (controllerInput != 0)
	{
		cin >> controllerInput;
		if (controllerInput == 1) {
			readySent = true;
			isInitiator = true;
			operationController = 1;
			new_session->deliver_to_Server("ready",2);

		}

		if (controllerInput == 2) {
			readySent = true;
			isInitiator = true;
			operationController = 2;
			new_session->deliver_to_Server("ready",2);

		}

		//		else if (controllerInput == 3) {
		//			readySent = true;
		//			isInitiator = true;
		//			operationController = 3;
		//			new_session->deliver_to_Server("ready",2);
		//		}

		else if (controllerInput == 4) {
			readySent = true;
			isInitiator = true;
			operationController = 4;
			new_session->deliver_to_Server("ready",2);
		}
		else if (controllerInput == 5) {



			try	{
				DeckAndOperations * deck  = new DeckAndOperations;
				deck->generateCardsAndPutIntoDeck();

				vector<CipherText> c = deck->deckVector;
				PermutationClass  pi(deck->deckVector.size());
				//				pi.makePi();

				vector<CipherText> cDoublePrime = c;
				deck->permutationShuffle(cDoublePrime, pi.map);
				vector<mpz_class>  r = deck->generateSecretRandomRVector(deck->pk.p, cDoublePrime.size());

				deck->re_mask_elGamal_deck(deck->pk,cDoublePrime, r);


				vector<CipherText> cPrime = c;
				vector<mpz_class>  rPrime = deck->generateSecretRandomRVector(deck->pk.p, cPrime.size());;
				PermutationClass  piPrime(cPrime.size());
				//				piPrime.makePiPrime();
				deck->permutationShuffle(cPrime,piPrime.map);
				deck->re_mask_elGamal_deck(deck->pk, cPrime, rPrime);



				PermutationClass  piDoublePrime(cPrime.size());
				piDoublePrime.map = piPrime.rmap;
				piDoublePrime.rmap = piPrime.map;

				deck->permutationShuffle(piDoublePrime.map,pi.map);
				cout << "\n------pi --------\n";
				for(auto i = pi.map.begin(); i != pi.map.end(); i++){
					cout << (*i) << " ";
				}
				cout << "\n------pi' --------\n";
				for(auto i = piPrime.map.begin(); i != piPrime.map.end(); i++){
					cout << (*i) << " ";
				}
				cout << "\n------pi' -1 ------ \n";
				for(auto i = piPrime.rmap.begin(); i != piPrime.rmap.end(); i++){
					cout << (*i) << " ";
				}

				cout << "\n------pi'' --------\n";
				for(auto i = piDoublePrime.map.begin(); i != piDoublePrime.map.end(); i++){
					cout << (*i) << " ";
				}
				vector<mpz_class>  rDoublePrime;
				vector<mpz_class>  tempRPrimeCombinedWithPiDoublePrime = rPrime;
				deck->permutationShuffle(tempRPrimeCombinedWithPiDoublePrime,piDoublePrime.map);


				int j = 0;
				for(auto i = r.begin(); i!= r.end();i++){
					rDoublePrime.push_back((*i) - tempRPrimeCombinedWithPiDoublePrime[j]);
					j++;
				}


				cout << "\n------r --------\n";
				for(auto i = r.begin(); i != r.end(); i++){
					cout << (*i) << std::endl;
				}
				cout << "\n------r' --------\n";
				for(auto i = rPrime.begin(); i != rPrime.end(); i++){
					cout << (*i) << std::endl;
				}

				cout << "\n------r'' --------\n";
				for(auto i = rDoublePrime.begin(); i != rDoublePrime.end(); i++){
					cout << (*i) << std::endl;
				}




				vector<CipherText> cThatMustBeEqualToCDoublePrimeInTheEnd = cPrime;

				deck->permutationShuffle(cThatMustBeEqualToCDoublePrimeInTheEnd,piDoublePrime.map);
				deck->re_mask_elGamal_deck(deck->pk,cThatMustBeEqualToCDoublePrimeInTheEnd,rDoublePrime);



				cout << "\n------C --------\n";
				for(auto i = c.begin(); i != c.end(); i++){
					cout << (*i)<< std::endl;
				}


				cout << "\n------C' --------\n";
				for(auto i = cPrime.begin(); i != cPrime.end(); i++){
					cout << (*i)<< std::endl;
				}

				cout << "\n------C'' --------\n";
				for(auto i = cDoublePrime.begin(); i != cDoublePrime.end(); i++){
					cout << (*i)<< std::endl;
				}

				cout << "\n----------set of cards applied by piDoublePrime and rDoublePrime on top of c'-------\n";

				for(auto i = cThatMustBeEqualToCDoublePrimeInTheEnd.begin(); i != cThatMustBeEqualToCDoublePrimeInTheEnd.end(); i++){
					cout << (*i) << std::endl;
				}






				sleep(1);

			}
			catch (std::exception& e)
			{
				std::cerr << "Exception: " << e.what() << "\n";
			}

		}

		else if (controllerInput == 6) {



			try	{
				DeckAndOperations * deck  = new DeckAndOperations;
				deck->generateCardsAndPutIntoDeck();
				deck->permutationClass = new PermutationClass(deck->deckVector.size());

				cout << "\n------Map--------\n";
				for(auto i = deck->permutationClass->map.begin(); i != deck->permutationClass->map.end(); i++){
					cout << (*i) << " ";
				}


				cout << "\n------Reverse Map--------\n";
				for(auto i = deck->permutationClass->rmap.begin(); i != deck->permutationClass->rmap.end(); i++){
					cout << (*i) << " ";
				}


				cout << "\n------Before Shuffle--------\n";
				for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
					cout << (*i) << " ";
				}
				deck->permutationShuffle(deck->deckVector, deck->permutationClass->map);
				cout << "\n------After Shuffle--------\n";
				for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
					cout << (*i)<< " ";
				}
				deck->permutationShuffle(deck->deckVector, deck->permutationClass->rmap);
				cout << "\n------After Reverse Shuffle--------\n";
				for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
					cout << (*i) << " ";
				}


				sleep(1);

			}
			catch (std::exception& e)
			{
				std::cerr << "Exception: " << e.what() << "\n";
			}


			//			}
		}
		else if (controllerInput == 7) {
			DeckAndOperations * deck  = new DeckAndOperations;
			deck->generateCardsAndPutIntoDeck();
			cout << "----------------Begin-------------- \n";

			for(size_t i = 0; i < deck->deckVector.size();i++){
				CipherText ct = deck->deckVector.at(i);
				ct = deck->mask_elGamal_with_Secret_Key(deck->pk, ct, NULL);

				cout << "----------------After Mask-------------- \n";
				std::cout << ct << std::endl;

			}

			for(size_t i = 0; i < deck->deckVector.size();i++){
				CipherText ct = deck->deckVector.at(i);
				ct = deck->unmask_elGamal_with_SecretKey(deck->pk, ct);
				//							ct = deck->finalize_unmask_elGamal(deck->pk, ct);
				cout << "----------------After Unmask-------------- \n";
				std::cout << ct << std::endl;
			}



		}
		else if (controllerInput == 8) {
			DeckAndOperations * deck = new DeckAndOperations;
			deck->generateCardsAndPutIntoDeck();
			CipherText cOne, cTwo;
			cOne = deck->deckVector.at(0);
			cTwo = deck->deckVector.at(0);
			cOne = deck->mask_elGamal(deck->pk, cOne, NULL);
			mpz_class rPrime = deck->secretRandomR(deck->pk.p);

			cout << "--------------c1----------------"<< std::endl;
			cout << cOne << std::endl;

			cTwo = deck->mask_elGamal(deck->pk, cTwo, &rPrime);
			cout << "--------------c2'----------------"<< std::endl;
			cout << cTwo << std::endl;

			mpz_class aTwoInvert(cTwo.c_1);
			mpz_invert(aTwoInvert.get_mpz_t(),aTwoInvert.get_mpz_t(),deck->pk.p.get_mpz_t());

			cout << "--------------a1 / a2----------------"<< std::endl;
			cout << cOne.c_1/cTwo.c_1 << std::endl;

			cout << "-------------a1 * aTwoInvert----------------"<< std::endl;
			cout << cOne.c_1*aTwoInvert%deck->pk.p << std::endl;

			cout << "--------------r'----------------"<< std::endl;
			cout << rPrime << std::endl;
			mpz_class mDoublePrime ;
			mpz_class rTriplePrime = deck->secretRandomR(deck->pk.p);

			cout << "--------------r'''----------------"<< std::endl;
			cout << rTriplePrime << std::endl;
			mpz_powm(mDoublePrime.get_mpz_t(), deck->pk.g.get_mpz_t(), rTriplePrime.get_mpz_t(), deck->pk.p.get_mpz_t());

			mpz_class rDoublePrime = deck->secretRandomR(deck->pk.p);
			mpz_class g_To_rDoublePRime;
			mpz_powm(g_To_rDoublePRime.get_mpz_t(), deck->pk.g.get_mpz_t(), rDoublePrime.get_mpz_t(),deck->pk.p.get_mpz_t());
			cout << "--------------r''----------------"<< std::endl;
			cout << rDoublePrime << std::endl;
			cout << "--------------g^r''----------------"<< std::endl;
			cout << g_To_rDoublePRime << std::endl;
			mpz_class g_To_XRDoublePRime = deck->getEncryptedSecret();
			mpz_powm(g_To_XRDoublePRime.get_mpz_t(), g_To_XRDoublePRime.get_mpz_t(), rDoublePrime.get_mpz_t(),deck->pk.p.get_mpz_t());
			cout << "--------------g^xa r''----------------"<< std::endl;
			cout << g_To_XRDoublePRime << std::endl;


			mpz_class bTwoInvert(cTwo.c_2);
			mpz_invert(bTwoInvert.get_mpz_t(),bTwoInvert.get_mpz_t(),deck->pk.p.get_mpz_t());
			CipherText cThree((cOne.c_1* aTwoInvert *g_To_rDoublePRime)%deck->pk.p ,( mDoublePrime* cOne.c_2 * bTwoInvert * g_To_XRDoublePRime) %deck->pk.p);

			cout << "--------------a3,b3----------------"<< std::endl;
			cout << cThree << std::endl;

			cout << "------------Xa-------------" << std::endl;
			cout << deck->getSecretKey()<< std::endl;

			CipherText mPrimeCT = deck->finalize_unmask_elGamal(deck->pk, cThree);
			mpz_class mPrime = mPrimeCT.c_1 * mPrimeCT.c_2;
			cout << "------------m'-------------" << std::endl;
			cout << mPrimeCT<< std::endl;



			cout << "------------m''-------------" << std::endl;
			cout << mDoublePrime<< std::endl;

			mpz_class g_To_rTriplePrime;
			mpz_powm(g_To_rTriplePrime.get_mpz_t(), deck->pk.g.get_mpz_t(), rTriplePrime.get_mpz_t(),deck->pk.p.get_mpz_t());

			cout << "------------g^r'''-------------" << std::endl;
			cout << g_To_rTriplePrime<< std::endl;

		}




		else if (controllerInput == 9) {
			DeckAndOperations * deck = new DeckAndOperations;
			deck->generateCardsAndPutIntoDeck();
			CipherText cOne, cTwo, cThree, cFour;
			cOne = deck->deckVector.at(0);
			cTwo = deck->deckVector.at(0);


			mpz_class spk = deck->getEncryptedSecret();
			mpz_class Xb = deck->secretRandomR(deck->pk.p);
			mpz_powm(deck->Shared_Public_Key.get_mpz_t(), spk.get_mpz_t(), Xb.get_mpz_t(), deck->pk.p.get_mpz_t() );

			mpz_class r = deck->secretRandomR(deck->pk.p);
			cOne = deck->mask_elGamal_with_Secret_Key(deck->pk, cOne, &r);
			mpz_class rPrime = deck->secretRandomR(deck->pk.p);
			cTwo = deck->mask_elGamal(deck->pk, cTwo, &rPrime);

			mpz_class rDoublePrime = deck->secretRandomR(deck->pk.p);
			CipherText mPrime (deck->secretRandomR(deck->pk.p));
			cThree = deck->mask_elGamal_with_Secret_Key(deck->pk, mPrime, &r);
			cThree = deck->mask_elGamal_with_Secret_Key(deck->pk, cThree, &rDoublePrime);


			cFour = deck->mask_elGamal(deck->pk, mPrime, &rPrime);
			cFour = deck->mask_elGamal(deck->pk, cFour, &rDoublePrime);



			cout << "------------b3-------------" << std::endl;
			cout << cThree.c_2<< std::endl;
			mpz_class mPrimeOverM = mPrime.c_2 / deck->deckVector.at(0).c_2;



			mpz_class encryptedSecretOverRdoublePrime;
			mpz_powm(encryptedSecretOverRdoublePrime.get_mpz_t(),spk.get_mpz_t(),rDoublePrime.get_mpz_t(), deck->pk.p.get_mpz_t());
			mpz_class calculationForBThree = (cOne.c_2 *mPrimeOverM * encryptedSecretOverRdoublePrime) % deck->pk.p;
			cout << "------------b1*m'/m*g^xar''-------------" << std::endl;

			cout << calculationForBThree<< std::endl;




		}
		else if (controllerInput == 10) {
			DeckAndOperations * deck = new DeckAndOperations;
			deck->generateCardsAndPutIntoDeck();
			CipherText cTOne, cTTwo;
			cTOne = deck->deckVector.at(0);
			cTOne = deck->mask_elGamal_with_Secret_Key(deck->pk, cTOne, NULL);

			mpz_class aOne = cTOne.c_1;
			mpz_class aTwo;
			mpz_powm(aTwo.get_mpz_t(),aOne.get_mpz_t(),deck->getSecretKey().get_mpz_t(),deck->pk.p.get_mpz_t());

			mpz_class aThree;
			mpz_class r = deck->secretRandomR(deck->pk.p);
			mpz_powm(aThree.get_mpz_t(),aOne.get_mpz_t(),r.get_mpz_t(),deck->pk.p.get_mpz_t());

			mpz_class aFour;
			mpz_powm(aFour.get_mpz_t(),aThree.get_mpz_t(),deck->getSecretKey().get_mpz_t(),deck->pk.p.get_mpz_t());

			mpz_class aOne_to_r;
			mpz_powm(aOne_to_r.get_mpz_t(),aOne.get_mpz_t(),r.get_mpz_t(),deck->pk.p.get_mpz_t());

			mpz_class aTwo_to_r;
			mpz_powm(aTwo_to_r.get_mpz_t(),aTwo.get_mpz_t(),r.get_mpz_t(),deck->pk.p.get_mpz_t());

			cout << "------------a1-------------" << std::endl;
			cout << aOne<< std::endl;
			cout << "------------a2-------------" << std::endl;
			cout << aTwo<< std::endl;
			cout << "------------a3-------------" << std::endl;
			cout << aThree<< std::endl;
			cout << "------------a4-------------" << std::endl;
			cout << aFour<< std::endl;
			cout << "------------a1^r-------------" << std::endl;
			cout << aOne_to_r<< std::endl;
			cout << "------------a2^r-------------" << std::endl;
			cout << aTwo_to_r<< std::endl;

		}
	}





	t.join();

	return 0;
}

