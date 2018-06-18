/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.cpp
 * Author: rigo
 *
 * Created on April 23, 2018, 9:22 PM
 */

#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <gmpxx.h>


#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <deque>

#include "CardClass.h"
#include "DeckAndOperations.h"
#include "game_message.hpp"


#include <random>


#include "bigint.h"

using boost::asio::ip::tcp;
std::string portNoGlobal;
bool readySent = false;
bool sharedSecretSent = false;
bool isLeader = false;


template<class Generator>
void initMerssenneTwister(Generator &gen) {
	size_t k = (Generator::word_size + 31) / 32;
	size_t seeds = k * Generator::state_size;

	std::random_device dev;
	std::uniform_int_distribution<uint32_t> dist;

	std::vector<uint32_t> v;
	for (size_t i=0; i<seeds; i++) {
		v.push_back(dist(dev));
	}

	std::seed_seq seq(v.begin(), v.end());
	gen.seed(seq);
}

template <class T>
void sendVector(tcp::socket &socket, const std::vector<T> &data) {
	size_t size = data.size() * sizeof(T);
	boost::asio::write(socket, boost::asio::buffer(&size, sizeof(size)));
	boost::asio::write(socket, boost::asio::buffer(data));
}

template <class T>
std::vector<T> receiveVector(tcp::socket &socket) {
	size_t size;

	boost::asio::read(socket, boost::asio::buffer(&size, sizeof(size)));
	std::vector<T> r(size / sizeof(T));
	boost::asio::read(socket, boost::asio::buffer(r));
	cout << " r returned \n";
	return r;

}

//----------------------------------------------------------------------------
typedef std::deque<game_message> game_message_queue;


//----------------------------------------------------------------------







//-----------------------------------------------------------------------------------------------------

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

	game_message read_msg_;
	game_message_queue write_msgs_;
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
	void server_handle_readMsg(const boost::system::error_code& err) {
		if (err) {
			cout << "ERROR: readMsg" << std::endl;
		} else {
			cout << "Incoming message: " << server_readMsg.data  << "\n Size: " << server_readMsg.header.size << "\n Message type: "
					<< server_readMsg.header.type << std::endl;
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
				if(!isLeader){
					deliver(deck->pk.p.get_str(10),101);
				}
			}
			else if(server_readMsg.header.type == 102){
				deck->pk.g= server_readMsg.data;
				cout << "g is : " << deck->pk.g << std::endl;
				if(!isLeader){
					deliver(deck->pk.g.get_str(10),102);
				}
			}
			else if(server_readMsg.header.type == 100){
				if(isLeader){
					if(!sharedSecretSent){
						deck->Shared_Secret_Key = server_readMsg.data;
						sharedSecretSent = true;
						deliver(deck->Shared_Secret_Key.get_str(10),100);
						cout << "SHARED SECRET KEY IS : " << deck->Shared_Secret_Key << std::endl;
					}
					else {
						deck->generateCardsAndPutIntoDeck();
					}
				}else{
					if(!sharedSecretSent){
						deck->generateSecretKey(&deck->pk);		//since we set public key by sending p and g we find a new secret key as we get x tilda generation
						mpz_class input(server_readMsg.data);
						sharedSecretSent = true;
						deliver(deck->contributeToSharedSecret(input).get_str(10),100);
					}
					else {
						deck->Shared_Secret_Key = server_readMsg.data;
						cout << "SHARED SECRET KEY IS : " << deck->Shared_Secret_Key << std::endl;
						deliver(deck->Shared_Secret_Key.get_str(10),100);
					}
				}

			}
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
			cout << "game_session_left start() \n";
			client_connected = true;
			client_startSending();
		}
	}
	/*
	 * wait = 1
	 * ready = 2
	 * start = 3
	 * EncryptedSecret = 100
	 * p = 101
	 * g = 102
	 * send deck to shuffle = 200
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
			cout << "Sent Message!" << std::endl;
			client_sendQueue.pop_front();
			client_startSending();
		}
	}

	//	void join_participant_out () {
	//		room_.join(shared_from_this());
	//	}

	void deliver(const std::string& msg, uint32_t type)
	{
		cout << "game_session_left deliver() \n";

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
	cout<<"Press 3 to Ready! signal. "<<endl;
	cout<<"Press 8 to Send chat messages!. "<<endl;

	cout<<"Press 0 to Terminate "<<endl;
	cout<<"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"<<endl;
	while (controllerInput != 0)
	{
		cin >> controllerInput;
		if (controllerInput == 1) {
			readySent = true;
			isLeader = true;
			new_session->deliver("ready",2);

		}
		else if (controllerInput == 2) {



			try	{
				DeckAndOperations * deck  = new DeckAndOperations;
				mpz_class encryptedSecret (deck->getEncryptedSecret());
				new_session->deliver(encryptedSecret.get_str(10),100);

				sleep(1);

			}
			catch (std::exception& e)
			{
				std::cerr << "Exception: " << e.what() << "\n";
			}


			//			}
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



	//Start 1st peer
	//All others connects to that peer
	//1st peer builds a ring

	t.join();

	return 0;
}
