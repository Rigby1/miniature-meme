/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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

#include "CardClass.h"
#include "DeckAndOperations.h"


#include <random>



using boost::asio::ip::tcp;
std::string portNoGlobal;
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
		cout << "------ Server Read Message" << std::endl;

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
	vector<CipherText> shuffledDeckVectorTemp;
	vector<size_t> recievedPiPrimeVector, recievedPiDoublePrimeVector;
	PermutationClass * tempPermuatationClassForZKIP;
	mpz_class randomS;
	vector<mpz_class> rVectorForInitiatior, rVectorForOthers, rPrimeVector, receivedRPrimeVector, recievedRDoublePrimeVector;
	void server_handle_readMsg(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: readMsg" << std::endl;
		} else {

			//			cout << "Incoming message: " << server_readMsg.data  << "\n Size: " << server_readMsg.header.size << "\n Message type: "
			//					<< server_readMsg.header.type << std::endl;
			if(server_readMsg.header.type == 2) {
				if(readySent == false){
					readySent = true;
					deliver_to_Server("ready" , 2);
				}
				else {// this is else is for the one who creates deck and pk
					try	{
						deliver_to_Server(deck->pk.p.get_str(10),101);
						deliver_to_Server(deck->pk.g.get_str(10),102);
						deliver_to_Server(deck->getEncryptedSecret().get_str(10),100);

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
			else if(server_readMsg.header.type == 201){
				c1 = server_readMsg.data;

			}
			else if(server_readMsg.header.type == 202){
				c2 = server_readMsg.data;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				shuffledDeckVectorTemp.push_back(ct);
			}
			else if(server_readMsg.header.type == 203){
				deck->deckVector = shuffledDeckVectorTemp;
				shuffledDeckVectorTemp.clear();
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
				shuffledDeckVectorTemp.push_back(ct);

			}
			else if(server_readMsg.header.type == 206){
				if(!isInitiator){
					deck->deckVector = shuffledDeckVectorTemp;
					shuffledDeckVectorTemp.clear();
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
					for(auto i = shuffledDeckVectorTemp.begin(), j = deck->deckVector.begin(); i!= shuffledDeckVectorTemp.end() && j!=  deck->deckVector.end();i++ , j++){
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
						shuffledDeckVectorTemp.clear();
					}
					//maskedDeckVector and maskedDeckVectorTemp should be exactly same
					//the comparison should be done here

					//					cout << "------START OF PROVING CORRECT SHUFFLING------" << std::endl;
					//					tempPermuatationClassForZKIP = new PermutationClass(deck->deckVector.size()); //this is pi'
					//					cout << "pi prime is: " << std::endl;
					//					for(auto i = tempPermuatationClassForZKIP->map.begin() ; i != tempPermuatationClassForZKIP->map.end(); i++) {
					//						cout << *i << "  ";
					//					}
					//					cout << std::endl;
					//					rPrimeVector = deck->generateSecretRandomRVector(deck->pk.p,deck->deckVector.size()); //this is r prime
					//					cout << "rPrimeVector is: " << std::endl;
					//
					//					cout << "--------------- Current DeckVector is -------------" << std::endl;
					//					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
					//						cout << *i << std::endl;
					//					}
					//
					//					shuffledDeckVectorTemp = deck->deckVector;
					//					deck->permutationShuffle(maskedDeckVectorTemp,tempPermuatationClassForZKIP->map);
					//					deck->re_mask_elGamal_deck(deck->pk,maskedDeckVectorTemp,rPrimeVector);
					//
					//					cout << "------------ SENDING REMASKED AND RESHUFFLED SET OF CARDS-------" << std::endl;
					//
					//					for(auto i = maskedDeckVectorTemp.begin(); i != maskedDeckVectorTemp.end(); i++){
					//						cout << (*i) << std::endl;
					//						deliver(i->c_1.get_str(10),401);
					//						deliver(i->c_2.get_str(10),402);
					//					}
					//					deliver("Remasked and Reshuffled Vector sent", 403);

					switch (operationController) {
					case 1 :  // UNSHUFFLE PROGRESS IS STARTED BY INITATIOR HERE
						cout << "------------8 - sending deckVector to unshuffle------------" << std::endl;
//						deck->permutationShuffle(deck->deckVector,deck->permutationClass->map);
//
//						for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
//							deliver_to_Server(i->c_1.get_str(10),301);
//							deliver_to_Server(i->c_2.get_str(10),302);
//						}
//						deliver_to_Server("Masked Deck Vectors should be all same", 303);
						deliver_to_Client("HALLOOOOOO",123);
					}


				}

			}

			else if(server_readMsg.header.type == 301){

				c1 = server_readMsg.data;

			}
			else if(server_readMsg.header.type == 302){

				c2 = server_readMsg.data;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				shuffledDeckVectorTemp.push_back(ct);

			}
			else if(server_readMsg.header.type == 303){

				if(!isInitiator){
					cout << "------------9 - Received deckVector to unshuffle------------" << std::endl;

					deck->permutationShuffle(shuffledDeckVectorTemp,deck->permutationClass->map);
					cout << "------------10 - reverse permutation applied deckVector to unshuffle------------" << std::endl;
					cout << "------------CONTENT OF  deckVector to after applied reverse map------------" << std::endl;

					for(auto i = shuffledDeckVectorTemp.begin(); i != shuffledDeckVectorTemp.end(); i++){
						cout << (*i) << std::endl;
						deliver_to_Server((*i).c_1.get_str(10),301);
						deliver_to_Server((*i).c_2.get_str(10),302);
					}
					shuffledDeckVectorTemp.clear();
					deliver_to_Server("sending completed for unshuffle",303);
//					deliver_to_Client("asdasdasdasdasdasdasdasd",123);
				}
				else {
					deck->deckVector = shuffledDeckVectorTemp;
					cout << "------------CONTENT OF  deckVector to after applied reverse map by all peers------------" << std::endl;

					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
						cout << (*i) << std::endl;
//						deliver((*i).c_1.get_str(10),306);
//						deliver((*i).c_2.get_str(10),307);
					}
					cout << "------------9 - SENDING UNSHUFFLED DECK TO SYNRONIZE------------" << std::endl;

//					deliver("All vectors should be same",308);

					shuffledDeckVectorTemp.clear();
				}

			}
			else if(server_readMsg.header.type == 306){
				c1 = server_readMsg.data;


			}
			else if(server_readMsg.header.type == 307){
				c2 = server_readMsg.data;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				shuffledDeckVectorTemp.push_back(ct);


			}
			else if(server_readMsg.header.type == 308){
				if(!isInitiator){
					deck->deckVector = shuffledDeckVectorTemp;
					cout << "------------10 - RECEIVED UNSHUFFLED DECK TO SYNRONIZE------------"<< std::endl;
				}
				else{
					bool synronizeUnshuffledDeck = true;
					cout << "------------CONTENT OF UNSHUFLLED DECK IN SYNCRONIZATION PHASE------------" << std::endl;
					for(auto i = shuffledDeckVectorTemp.begin(), j = deck->deckVector.begin(); i!= shuffledDeckVectorTemp.end() && j!=  deck->deckVector.end();i++ , j++){
						cout << *i << std::endl;
						if((*j).c_1 != (*i).c_1 && (*j).c_2 != (*i).c_2) {
							synronizeUnshuffledDeck = false;
						}
					}

					if(synronizeUnshuffledDeck == false) {
						cout << "ERROR: SOMEONE IS CHEATING DURING SYNCRONIZATION OF UNSHUFFLED DECK" << std::endl;
					}
					else {
						cout << "------------11 - reshuffled vectors are all same in each node------------" << std::endl;
						shuffledDeckVectorTemp.clear();
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
				shuffledDeckVectorTemp.push_back(ct);
			}
			else if(server_readMsg.header.type == 403){
				// Deciede on S
				mpz_class randomS(1);
				//				mpz_class randomS = deck->secretRandomR(deck->pk.p);
				//				randomS = randomS % 2;

				deliver_to_Server(randomS.get_str(10),404);
			}

			else if(server_readMsg.header.type == 404){
				mpz_class randomSTemp(server_readMsg.data);
				if(randomSTemp == 0) {
					cout << "-*-*-*-*- Sending RPRIME IS : "  << std::endl;
					for(auto i = rPrimeVector.begin(); i!= rPrimeVector.end();i++){
						cout<< (*i) << std::endl;
						deliver_to_Server((*i).get_str(10),405);
					}
					deliver_to_Server("Sending r prime completed",415);

					for(auto i = tempPermuatationClassForZKIP->map.begin(); i != tempPermuatationClassForZKIP->map.end() ; i++) {
						mpz_class fromSize_tToMpz (*i);
						deliver_to_Server(fromSize_tToMpz.get_str(10),406);
					}
					deliver_to_Server("Sending pi' completed", 407);
				}
				else if (randomSTemp == 1) {
					PermutationClass piDoublePrime(deck->deckVector.size());
					piDoublePrime.map = tempPermuatationClassForZKIP->rmap;
					piDoublePrime.rmap = tempPermuatationClassForZKIP->map;
					deck->permutationShuffle(piDoublePrime.map, deck->permutationClass->map);



					vector<mpz_class> rDoublePrimeVector;
					vector<mpz_class> tempRprimeVector = rPrimeVector;
					deck->permutationShuffle(tempRprimeVector, piDoublePrime.map);
					int j = 0;
					for(auto i = tempRprimeVector.begin(); i!= tempRprimeVector.end();i++){
						cout << "r: " << rVectorForInitiatior[j] << " r'PermutatedwithpiDoublePrime :" << (*i) << "substitution : " << rVectorForInitiatior[j] - (*i) << std::endl;
						rDoublePrimeVector.push_back(rVectorForInitiatior[j] - (*i));
						j++;
					}
					cout << "------ R Double prime is :" <<  std::endl;


					for(auto i = rDoublePrimeVector.begin(); i!= rDoublePrimeVector.end();i++){
						cout<< (*i) << " ";
						deliver_to_Server((*i).get_str(10),408);
					}
					cout << "Sending r'' completed " <<std::endl;
					deliver_to_Server("Sending r double prime Completed!",418);


					cout << "------ Content of Pi Double prime is " << std::endl;
					for(auto i = piDoublePrime.map.begin(); i!= piDoublePrime.map.end();i++){
						mpz_class fromSize_tToMpz (*i);
						cout << "pi'' :" <<  fromSize_tToMpz.get_str(10) << " ";
						deliver_to_Server(fromSize_tToMpz.get_str(10),409);
					}
					cout << "Sending pi'' completed " <<std::endl;
					deliver_to_Server("Sending Completed!",410);




				}
				else {
					std::cerr << "error: " << "\n";
				}

			}

			else if(server_readMsg.header.type == 405){
				mpz_class receivedrPrime(server_readMsg.data);
				receivedRPrimeVector.push_back(receivedrPrime);
				std::cout << "Received r' :  " <<  server_readMsg.data << std::endl;

			}
			else if(server_readMsg.header.type == 406){
				size_t tmpSize_t = 0;
				sscanf(server_readMsg.data.c_str(),"%zu", &tmpSize_t);
				recievedPiPrimeVector.push_back(tmpSize_t);
				std::cout << "Received pi' :  " <<  tmpSize_t << " ";


			}
			else if(server_readMsg.header.type == 407){
				std::cout << "Received pi' completed" << std::endl;
				vector<CipherText> secondTempDeck = deck->deckVector;
				deck->permutationShuffle(secondTempDeck,recievedPiPrimeVector);
				deck->re_mask_elGamal_deck(deck->pk,secondTempDeck,receivedRPrimeVector);
				cout << "-------------------------COMPARISON -- content OF C' ----------------------" << std::endl;
				for(auto i = secondTempDeck.begin(); i!= secondTempDeck.end();i++){
					cout << (*i) << std::endl;
				}
				cout << "-------------------------COMPARISON -- content OF C ----------------------" << std::endl;
				for(auto i = shuffledDeckVectorTemp.begin(); i!= shuffledDeckVectorTemp.end();i++){
					cout << (*i) << std::endl;
				}

				bool cheatDetected = false;
				for(auto i = secondTempDeck.begin(), j = shuffledDeckVectorTemp.begin(); i!= secondTempDeck.end() && j!= shuffledDeckVectorTemp.end();i++ , j++){
					if((*j).c_1 != (*i).c_1 && (*j).c_2 != (*i).c_2) {
						cheatDetected = true;
					}
				}
				if(cheatDetected){
					cout << "------ CHEAT DETECTED ------ \nCheat detected while comparing c and c'" << std::endl;
				}
				else{
					cout << "--------------- COMPARISON OF C AND C' IS OKAY - ZERO KNOWLEDGE INTERACTIVE PROOF WORKED------------" << std::endl;
				}



			}
			else if(server_readMsg.header.type == 408){
				mpz_class recievedRDoublePrime (server_readMsg.data);
				recievedRDoublePrimeVector.push_back(recievedRDoublePrime);
				std::cout << "Received r'' :  " <<  server_readMsg.data << std::endl;
			}
			else if(server_readMsg.header.type == 409){
				size_t tmpSize_t = 0;
				sscanf(server_readMsg.data.c_str(),"%zu", &tmpSize_t);
				recievedPiDoublePrimeVector.push_back(tmpSize_t);
				std::cout << "Received pi'' :  " <<  tmpSize_t << " ";
			}

			else if(server_readMsg.header.type == 410){
				std::cout << "Received pi'' completed" << std::endl;
				vector<CipherText> secondTempDeck = shuffledDeckVectorTemp;
				cout <<"----------------C' before remask and permutate------------------\n";
				for(auto i = secondTempDeck.begin(); i != secondTempDeck.end(); i++){
					CipherText citext = deck->finalize_unmask_elGamal(deck->pk,*i);
					cout << citext << std::endl;
				}
				deck->permutationShuffle(secondTempDeck,recievedPiDoublePrimeVector);
				deck->re_mask_elGamal_deck(deck->pk,secondTempDeck,recievedRDoublePrimeVector);


				cout << "-------------------------COMPARISON -- content OF C'' ----------------------" << std::endl;
				for(auto i = secondTempDeck.begin(); i!= secondTempDeck.end();i++){
					cout << (*i) << std::endl;
				}
				cout << "-------------------------COMPARISON -- content OF C ----------------------" << std::endl;
				for(auto i = deck->deckVector.begin(); i!= deck->deckVector.end();i++){
					cout << (*i) << std::endl;
				}

				bool cheatDetected = false;
				for(auto i = secondTempDeck.begin(), j = deck->deckVector.begin(); i!= secondTempDeck.end() && j!=  deck->deckVector.end();i++ , j++){
					if((*j).c_1 != (*i).c_1 && (*j).c_2 != (*i).c_2) {
						cheatDetected = true;
					}
				}
				if(cheatDetected){
					cout << "------ CHEAT DETECTED ------ \nCheat detected while comparing c and c'' (CASE 2)" << std::endl;
				}
				else{
					cout << "--------------- COMPARISON OF C AND C'' IS OKAY - ZERO KNOWLEDGE INTERACTIVE PROOF WORKED------------" << std::endl;
				}
			}
			else if(server_readMsg.header.type == 415){
				std::cout << "Receiveing r' Completed" << std::endl;
			}
			else if(server_readMsg.header.type == 418){
				std::cout << "Receiveing r'' Completed" << std::endl;
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
		//		cout << "Enter port number to connect: ";
		//		string portNo;
		//		cin >> portNo;
		//		cout << "Resolving " << portNoGlobal << std::endl;
		tcp::resolver::query query("localhost", portNoGlobal);
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

			//			cout << "Sent Message!" << std::endl;
			client_sendQueue.pop_front();
			client_startSending();

			//			  thr.join();
		}
	}

	//	void join_participant_out () {
	//		room_.join(shared_from_this());
	//	}

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
	//virtual_table room;





	cout << "Enter port number to open: ";
	int portNumber;
	cin >> portNumber;

	cout << "Enter port number to connect: ";
	cin >> portNoGlobal;


	tcp::endpoint endpoint(tcp::v4(), portNumber);
	game_session_ptr new_session(new game_session(io_service, endpoint));
	new_session->server_accept();
	new_session->client_schedule_connect();


	sleep(1);

	int controllerInput = 9;
	cout<<"\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"<<endl;
	cout<<"Press appropriate key:"<<endl;
	cout<<"Press 1 to Shuffle with Multiple players. Prove in the end!"<<endl;
	cout<<"Press 2 to Create Deck and agree on secret key. " <<endl;
	cout<<"Press 3 to Zero Knowledge Interactive Proof. "<<endl;
	cout<<"Press 8 to Send chat messages!. "<<endl;

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
		else if (controllerInput == 2) {



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
				//
				//    cout << "----------------Begin-------------- \n";
				//    vector<CardClass*> deckVector = deck->getDeck();
				//    for(auto i = deckVector.begin(); i != deckVector.end(); i++){
				//        gmp_printf ("%s is %Zd\n", "id", (*i)->id);
				//        CipherText ct((*i)->id);
				//
				//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
				//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
				//
				//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
				//
				//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
				//
				//        std::cout << ct << std::endl;
				//        ct = deck->unmask_elGamal(deck->pk, ct);
				//
				//        std::cout << ct << std::endl;
				//
				//        //deck->decode(p,q,r,x,(*i)->id);
				//    }
				//    deck->reversePermutationShuffle(permutatedVectorThree);
				//    deck->reversePermutationShuffle(permutatedVectorTwo);
				//    deck->reversePermutationShuffle(permutatedVector);
				//
				//    vector<CardClass*> deckVectorTwo = deck->getDeck();
				//    for(auto i = deckVectorTwo.begin(); i != deckVectorTwo.end(); i++){
				//        gmp_printf ("%s is %Zd\n", "id", (*i)->id);
				//    }


				sleep(1);

			}
			catch (std::exception& e)
			{
				std::cerr << "Exception: " << e.what() << "\n";
			}


			//			}
		}

		else if (controllerInput == 3) {



			try	{
				DeckAndOperations * deck  = new DeckAndOperations;
				deck->generateCardsAndPutIntoDeck();

				vector<CipherText> c = deck->deckVector;
				PermutationClass  pi(deck->deckVector.size());
				pi.makePi();

				vector<CipherText> cDoublePrime = c;
				deck->permutationShuffle(cDoublePrime, pi.map);
				vector<mpz_class>  r = deck->generateSecretRandomRVector(deck->pk.p, cDoublePrime.size());

				deck->re_mask_elGamal_deck(deck->pk,cDoublePrime, r);


				vector<CipherText> cPrime = c;
				vector<mpz_class>  rPrime = deck->generateSecretRandomRVector(deck->pk.p, cPrime.size());;
				PermutationClass  piPrime(cPrime.size());
				piPrime.makePiPrime();
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
		else if (controllerInput == 5) {
			DeckAndOperations * deck  = new DeckAndOperations;
			deck->generateCardsAndPutIntoDeck();
			PermutationClass p1(deck->deckVector.size(),true);
			PermutationClass p2(deck->deckVector.size(),true);
			PermutationClass p3(deck->deckVector.size(),true);
			PermutationClass p4(deck->deckVector.size(),true);
			deck->permutationShuffle(deck->deckVector,p1.map);
			deck->permutationShuffle(deck->deckVector,p2.map);
			deck->permutationShuffle(deck->deckVector,p3.map);
//			deck->permutationShuffle(deck->deckVector,p4.map);
			deck->permutationShuffle(deck->deckVector,p1.map);
			deck->permutationShuffle(deck->deckVector,p2.map);
			deck->permutationShuffle(deck->deckVector,p3.map);
//			deck->permutationShuffle(deck->deckVector,p4.map);

			for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
				cout << (*i)<< std::endl;
			}

		}
	}



	//    DeckAndOperations * deck  = new DeckAndOperations;
	//    deck->generateCardsAndPutIntoDeck();
	//    vector<int> permutatedVector;
	//    vector<int> permutatedVectorTwo;
	//    vector<int> permutatedVectorThree;
	//
	//
	//    deck->permutationShuffle(&permutatedVector);
	//    deck->permutationShuffle(&permutatedVectorTwo);
	//    deck->permutationShuffle(&permutatedVectorThree);
	//
	//    cout << "----------------Begin-------------- \n";
	//    vector<CardClass*> deckVector = deck->getDeck();
	//    for(auto i = deckVector.begin(); i != deckVector.end(); i++){
	//        gmp_printf ("%s is %Zd\n", "id", (*i)->id);
	//        CipherText ct((*i)->id);
	//
	//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
	//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
	//
	//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
	//
	//        ct = deck->mask_elGamal(deck->pk, ct, NULL);
	//
	//        std::cout << ct << std::endl;
	//        ct = deck->unmask_elGamal(deck->pk, ct);
	//
	//        std::cout << ct << std::endl;
	//
	//        //deck->decode(p,q,r,x,(*i)->id);
	//    }
	//    deck->reversePermutationShuffle(permutatedVectorThree);
	//    deck->reversePermutationShuffle(permutatedVectorTwo);
	//    deck->reversePermutationShuffle(permutatedVector);
	//
	//    vector<CardClass*> deckVectorTwo = deck->getDeck();
	//    for(auto i = deckVectorTwo.begin(); i != deckVectorTwo.end(); i++){
	//        gmp_printf ("%s is %Zd\n", "id", (*i)->id);
	//    }


	t.join();

	return 0;
}

