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
	std::list<msg_t> client_sendQueue;
	bool          client_connected = false;

	tcp::acceptor acceptor;
	tcp::socket server_socket;
	msg_t       server_readMsg;

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
	vector<CipherText> maskedDeckVectorTemp;
	vector<size_t> recievedPiPrimeVector, recievedPiDoublePrimeVector;
	PermutationClass * tempPermuatationClassForZKIP;
	mpz_class randomS;
	vector<mpz_class> rVectorForInitiatior, rVectorForOthers, rPrimeVector, receivedRPrimeVector, recievedRDoublePrimeVector;
	bool unmaskInProgress = false;
	void server_handle_readMsg(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: readMsg" << std::endl;
		} else {

			//			cout << "Incoming message: " << server_readMsg.data  << "\n Size: " << server_readMsg.header.size << "\n Message type: "
			//					<< server_readMsg.header.type << std::endl;
			if(server_readMsg.header.type == 2) {
				if(readySent == false){
					readySent = true;
					deliver("ready" , 2);
				}
				else {// this is else is for the one who creates deck and pk
					try	{
						deliver(deck->pk.p.get_str(10),101);
						deliver(deck->pk.g.get_str(10),102);
						deliver(deck->getEncryptedSecret().get_str(10),100);

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
					deliver(deck->pk.p.get_str(10),101);
				}
			}
			else if(server_readMsg.header.type == 102){
				deck->pk.g= server_readMsg.data;
				cout << "g is : " << deck->pk.g << std::endl;
				if(!isInitiator){
					deliver(deck->pk.g.get_str(10),102);
				}
			}
			else if(server_readMsg.header.type == 100){
				if(isInitiator){
					if(!sharedPKSent){
						deck->Shared_Public_Key = server_readMsg.data;
						sharedPKSent = true;
						deliver(deck->Shared_Public_Key.get_str(10),100);
						cout << "PUBLIC SECRET KEY IS : " << deck->Shared_Public_Key << std::endl;
					}
					else {
						deck->generateCardsAndPutIntoDeck();
						vector<size_t> permutationVector;
						deck->permutationClass = new PermutationClass(deck->deckVector.size());
						deck->permutationShuffle(deck->deckVector, deck->permutationClass->map);
						//we need to send permutated(shuffled) deck to others in order them to shuffle as well
						cout << "--------------- DeckVector Before remask  -------------" << std::endl;
						for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
							cout << *i << std::endl;
						}

						rVectorForInitiatior = deck->generateSecretRandomRVector(deck->pk.p,deck->deckVector.size());
						vector<CipherText> cts= deck->re_mask_elGamal_deck(deck->pk, deck->deckVector, rVectorForInitiatior);// we use re_mask_elGamal_deck instead of mask_elGamal_deck() because
						cout << "--------------- DeckVector After remask  -------------" << std::endl;
						for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
							cout << *i << std::endl;
						}

						// we want to use r later for calculating r'' in zero knowledge interactive proof part
						for(auto i = cts.begin(); i != cts.end(); i++){
							//							cout << "Sending c1: " << i->c_1 << "\nSending c2: " << i->c_2 << std::endl;
							deliver(i->c_1.get_str(10),201);
							deliver(i->c_2.get_str(10),202);
						}
						deliver("done sending",203);

						//string msg_to_send = deck->convertCiphertTextsIntoString(cts);
						//						deliver(msg_to_send,500);


						//						ct = deck->mask_elGamal(deck->pk, ct, NULL);
						//						cout << "c1: " << ct.c_1 << "c2: " << ct.c_2 << std::endl;
					}
				}else{
					if(!sharedPKSent){
						deck->generateSecretKey(&deck->pk);		//since we set public key by sending p and g we find a new secret key as we get x tilda generation
						mpz_class input(server_readMsg.data);
						sharedPKSent = true;
						deliver(deck->contributeToSharedSecret(input).get_str(10),100);
					}
					else {
						deck->Shared_Public_Key = server_readMsg.data;
						cout << "SHARED PUBLIC KEY IS : " << deck->Shared_Public_Key << std::endl;
						deliver(deck->Shared_Public_Key.get_str(10),100);
					}
				}

			}
			else if(server_readMsg.header.type == 201){
				c1 = server_readMsg.data;
				//				cout << "Received c1 is : " <<  server_readMsg.data << std::endl;

			}
			else if(server_readMsg.header.type == 202){
				c2 = server_readMsg.data;
				//				cout << "Received c2 is : " <<  server_readMsg.data << std::endl;
				mpz_class cOne(c1);
				mpz_class cTwo(c2);
				CipherText ct(cOne,cTwo);
				maskedDeckVectorTemp.push_back(ct);
			}
			else if(server_readMsg.header.type == 203){
				deck->deckVector = maskedDeckVectorTemp;
				maskedDeckVectorTemp.clear();
				if(!isInitiator){
					deck->permutationClass = new PermutationClass(deck->deckVector.size());
					deck->permutationShuffle(deck->deckVector,deck->permutationClass->map);
					rVectorForOthers = deck->generateSecretRandomRVector(deck->pk.p,deck->deckVector.size());
					vector<CipherText> cts= deck->re_mask_elGamal_deck(deck->pk, deck->deckVector, rVectorForOthers); // we use re_mask_elGamal_deck instead of mask_elGamal_deck() because
					// we want to use r later for calculating r'' in zero knowledge interactive proof part
					for(auto i = cts.begin(); i != cts.end(); i++){
						//						cout << "Sending c1: " << i->c_1 << "\nSending c2: " << i->c_2 << std::endl;
						deliver(i->c_1.get_str(10),201);
						deliver(i->c_2.get_str(10),202);
					}
					deliver("done sending",203);
				}
				else {
					cout << "------------Received Shuffled and Masked Vector------------" << std::endl;
					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
						//						cout << "CT: " << *i << std::endl;
						deliver(i->c_1.get_str(10),204);
						deliver(i->c_2.get_str(10),205);
					}
					deliver("Masked Deck Vectors should be all same", 206);
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
				maskedDeckVectorTemp.push_back(ct);

			}
			else if(server_readMsg.header.type == 206){
				if(!isInitiator){
					deck->deckVector = maskedDeckVectorTemp;
					maskedDeckVectorTemp.clear();
					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
						//						cout << "CT: " << *i << std::endl;
						deliver(i->c_1.get_str(10),204);
						deliver(i->c_2.get_str(10),205);
					}
					deliver("Masked Deck Vectors should be all same", 206);
				}
				else {	//LEADER STARTS NEXT PHASE OF THE GAME FROM HERE
					maskedDeckVectorTemp.clear();
					//maskedDeckVector and maskedDeckVectorTemp should be exactly same
					//the comparison should be done here

					cout << "------START OF PROVING CORRECT SHUFFLING------" << std::endl;
					tempPermuatationClassForZKIP = new PermutationClass(deck->deckVector.size()); //this is pi'
					cout << "pi prime is: " << std::endl;
					for(auto i = tempPermuatationClassForZKIP->map.begin() ; i != tempPermuatationClassForZKIP->map.end(); i++) {
						cout << *i << "  ";
					}
					cout << std::endl;
					rPrimeVector = deck->generateSecretRandomRVector(deck->pk.p,deck->deckVector.size()); //this is r prime
					cout << "rPrimeVector is: " << std::endl;

					cout << "--------------- Current DeckVector is -------------" << std::endl;
					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
						cout << *i << std::endl;
					}

					maskedDeckVectorTemp = deck->deckVector;
					deck->permutationShuffle(maskedDeckVectorTemp,tempPermuatationClassForZKIP->map);
					deck->re_mask_elGamal_deck(deck->pk,maskedDeckVectorTemp,rPrimeVector);

					cout << "------------ SENDING REMASKED AND RESHUFFLED SET OF CARDS-------" << std::endl;

					for(auto i = maskedDeckVectorTemp.begin(); i != maskedDeckVectorTemp.end(); i++){
						cout << (*i) << std::endl;
						deliver(i->c_1.get_str(10),401);
						deliver(i->c_2.get_str(10),402);
					}
					deliver("Remasked and Reshuffled Vector sent", 403);

					//FOR NOW LEADER IS JUST UNMASKING
					//					unmaskInProgress = true;
					//					for(auto i = deck->deckVector.begin(); i != deck->deckVector.end(); i++){
					//						deliver(i->c_1.get_str(10),301);
					//						deliver(i->c_2.get_str(10),302);
					//					}
					//					deliver("Masked Deck Vectors should be all same", 303);

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
				maskedDeckVectorTemp.push_back(ct);

			}
			else if(server_readMsg.header.type == 303){
				if(!unmaskInProgress) {
					for(auto i = maskedDeckVectorTemp.begin(); i != maskedDeckVectorTemp.end(); i++){
						CipherText citext = deck->unmask_elGamal(deck->pk,*i);
						deliver(citext.c_1.get_str(10),301);
						deliver(citext.c_2.get_str(10),302);
					}
					maskedDeckVectorTemp.clear();
					deliver("sending completed for unmask",303);
				}
				else {
					//deck->reversePermutationShuffleForEncryptedVector(deck->permutationClass);
					cout << "----------------------After Unmask -----------------" << std::endl;
					for(auto i = maskedDeckVectorTemp.begin(); i != maskedDeckVectorTemp.end(); i++){
						CipherText citext = deck->finalize_unmask_elGamal(deck->pk,*i);
						cout << citext << std::endl;
					}
					unmaskInProgress = false;
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
				maskedDeckVectorTemp.push_back(ct);
			}
			else if(server_readMsg.header.type == 403){
				// Deciede on S
				mpz_class randomS = deck->secretRandomR(deck->pk.p);
				randomS = randomS % 2;
				deliver(randomS.get_str(10),404);
			}

			else if(server_readMsg.header.type == 404){
				mpz_class randomSTemp(server_readMsg.data);
				if(randomSTemp == 0) {
					cout << "-*-*-*-*- Sending RPRIME IS : "  << std::endl;
					for(auto i = rPrimeVector.begin(); i!= rPrimeVector.end();i++){
						cout<< (*i) << std::endl;
						deliver((*i).get_str(10),405);
					}
					deliver("Sending r prime completed",415);

					for(auto i = tempPermuatationClassForZKIP->map.begin(); i != tempPermuatationClassForZKIP->map.end() ; i++) {
						mpz_class fromSize_tToMpz (*i);
						deliver(fromSize_tToMpz.get_str(10),406);
					}
					deliver("Sending pi' completed", 407);
				}
				else if (randomSTemp == 1) {
					PermutationClass piDoublePrime;
					piDoublePrime.map = deck->permutationClass->map;
					piDoublePrime.rmap = deck->permutationClass->rmap;
					deck->permutationShuffle(piDoublePrime.map, tempPermuatationClassForZKIP->rmap);



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
						deliver((*i).get_str(10),408);
					}
					cout << "Sending r'' completed " <<std::endl;
					deliver("Sending r double prime Completed!",418);


					cout << "------ Content of Pi Double prime is " << std::endl;
					for(auto i = piDoublePrime.map.begin(); i!= piDoublePrime.map.end();i++){
						mpz_class fromSize_tToMpz (*i);
						cout << "pi'' :" <<  fromSize_tToMpz.get_str(10) << " ";
						deliver(fromSize_tToMpz.get_str(10),409);
					}
					cout << "Sending pi'' completed " <<std::endl;
					deliver("Sending Completed!",410);




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
				for(auto i = maskedDeckVectorTemp.begin(); i!= maskedDeckVectorTemp.end();i++){
					cout << (*i) << std::endl;
				}

				bool cheatDetected = false;
				for(auto i = secondTempDeck.begin(), j = maskedDeckVectorTemp.begin(); i!= secondTempDeck.end() && j!= maskedDeckVectorTemp.end();i++ , j++){
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
				vector<CipherText> secondTempDeck = maskedDeckVectorTemp;
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
	 * Completed all encrypted cards same all in each peer = 206
	 * unmask operation c1 = 301
	 * unmask operation c2 = 302
	 * unmask operation finalize = 303
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
		}
	}

	//	void join_participant_out () {
	//		room_.join(shared_from_this());
	//	}

	void deliver(const std::string& msg, uint32_t type)
	{
		//		cout << "game_session_left deliver() \n";

		io_service.post(boost::bind(&game_session::client_enqueueMessage, shared_from_this(), msg, type));

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
	cout<<"Press 1 to Start"<<endl;
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
			new_session->deliver("ready",2);

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

				vector<CipherText> cDoublePrime = c;
				deck->permutationShuffle(cDoublePrime, pi.map);
				vector<mpz_class>  r = deck->generateSecretRandomRVector(deck->pk.p, cDoublePrime.size());

				deck->re_mask_elGamal_deck(deck->pk,cDoublePrime, r);


				vector<CipherText> cPrime = c;
				vector<mpz_class>  rPrime = deck->generateSecretRandomRVector(deck->pk.p, cPrime.size());;
				PermutationClass  piPrime(cPrime.size());
				deck->permutationShuffle(cPrime,piPrime.map);
				deck->re_mask_elGamal_deck(deck->pk, cPrime, rPrime);




				PermutationClass  piDoublePrime(deck->deckVector.size());
				piDoublePrime.map = pi.map;
				piDoublePrime.rmap = pi.rmap;

				deck->permutationShuffle(piDoublePrime.map,piPrime.rmap);

				cout << "\n------pi --------\n";
				for(auto i = pi.map.begin(); i != pi.map.end(); i++){
					cout << (*i) << " ";
				}
				cout << "\n------pi' --------\n";
				for(auto i = piPrime.map.begin(); i != piPrime.map.end(); i++){
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
		//
		//		else if (controllerInput == 8) {
		//			cout << "Enter ip number to connect: ";
		//			string ipNumber;
		//			cin >> ipNumber;
		//			cout << "Enter port number to connect: ";
		//			string portNo;
		//			cin >> portNo;
		//
		//			tcp::resolver resolver(io_service);
		//			tcp::resolver::query query(ipNumber, portNo);
		//			tcp::resolver::iterator iterator = resolver.resolve(query);
		//
		//			try {
		//				peer_client c(io_service, iterator);
		//
		//				char line[game_message::max_body_length + 1];
		//				while (std::cin.getline(line, game_message::max_body_length + 1))
		//				{
		//					using namespace std; // For strlen and memcpy.
		//					game_message msg;
		//					msg.body_length(strlen(line));
		//					memcpy(msg.body(), line, msg.body_length());
		//					msg.encode_header();
		//					c.write(msg);
		//				}
		//
		//			}
		//			catch (std::exception& e)
		//			{
		//				std::cerr << "Exception: " << e.what() << "\n";
		//			}
		//		}
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

