#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <Windows.h>

//H3110 1 4M 4NDr0YD D'RA, 1 R3411Y 11K3 70 741K UNF0r7UN4731Y 1347H3r 8465 814M3 M3 7H47 1 C4rrY N0N53N53 8U7 M4Y83 17 W111 H4V3 47 13457 50M3 V41U3 F0r Y0U


typedef enum {
	PUSH = 0x1337be01,
	POP = 0x1337be05,
	// add two stack values, put result on stack
	ADD = 0x1337be02,
	// subtract two stack values, put result on stack
	SUB = 0x1337be06,
	// divide two stack values, put result on stack
	DIV = 0x1337be03,
	// multiply two stack values, put result on stack
	MUL = 0x1337be04,
	// put user input onto stack
	ENTER = 0x1337be11,
	// check last two stack values are equal
	TEST = 0x1337be09,
	// print stack last value
	PRINT = 0x1337be10,
	// print stack
	RAM = 0x13370208,
	// Exit vm
	EXIT = 0x13370207,
	SXOR = 0xdeadbeef

} mnemonics;



int VM = 1;
const int MAXMEM = 1024;

int stack[MAXMEM];

int sp = -1;
int f_sp = -1;
int ip = 0;


int empty_sp() {
	return sp == -1 ? 1 : 0;
}

int full_sp() {
	return sp == MAXMEM ? 1 : 0;
}
//char flag[] = "HSE{4HH_MY_53NP411111_I_4M_Y0Ur_F146_74K3_M3}";
//char kek[] = { 0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x17,0x5,0x11,0x17,0x6a,0x77,0x7e,0x1e,
//              0x3,0x6e,0x6,0x1,0x64,0x72,0x17,0x16,0x12,0x7,0x12,0x68,0x11,0x3,0x27,0x41,0x0,0x16,0x7d,0x7,0x5,0x6c,0x4,0x0,0x7e,0x0,0x6c,0x7e,0x0,0x0 };
char flag[100];

char secret[] = "HSE{0HHHHHH_D0N7_70UCH_M3_7H3r3_PL3333453333}";

SYSTEMTIME st;

const int generate_flag[] = {
	PUSH,0x0, PUSH, 'H', SXOR,
	PUSH,0x0, PUSH, 'S', SXOR,
	PUSH,0x0, PUSH, 'E', SXOR,
	PUSH,0x0, PUSH, '{', SXOR,
	PUSH,0x4, PUSH, '0', SXOR,
	PUSH,0x0, PUSH, 'H', SXOR,
	PUSH,0x0, PUSH, 'H', SXOR,
	PUSH,0x17,PUSH, 'H', SXOR,
	PUSH,0x5, PUSH, 'H', SXOR,
	PUSH,0x11,PUSH, 'H', SXOR,
	PUSH,0x17,PUSH, 'H', SXOR,
	PUSH,0x6a,PUSH, '_', SXOR,
	PUSH,0x77,PUSH, 'D', SXOR,
	PUSH,0x7e,PUSH, '0', SXOR,
	PUSH,0x1e,PUSH, 'N', SXOR,
	PUSH,0x3, PUSH, '7', SXOR,
	PUSH,0x6e,PUSH, '_', SXOR,
	PUSH,0x6, PUSH, '7', SXOR,
	PUSH,0x1, PUSH, '0', SXOR,
	PUSH,0x64,PUSH, 'U', SXOR,
	PUSH,0x72,PUSH, 'C', SXOR,
	PUSH,0x17,PUSH, 'H', SXOR,
	PUSH,0x16,PUSH, '_', SXOR,
	PUSH,0x12,PUSH, 'M', SXOR,
	PUSH,0x7, PUSH, '3', SXOR,
	PUSH,0x12,PUSH, '_', SXOR,
	PUSH,0x68,PUSH, '7', SXOR,
	PUSH,0x11,PUSH, 'H', SXOR,
	PUSH,0x3, PUSH, '3', SXOR,
	PUSH,0x27,PUSH, 'r', SXOR,
	PUSH,0x41,PUSH, '3', SXOR,
	PUSH,0x0, PUSH, '_', SXOR,
	PUSH,0x16,PUSH, 'P', SXOR,
	PUSH,0x7d,PUSH, 'L', SXOR,
	PUSH,0x7, PUSH, '3', SXOR,
	PUSH,0x5, PUSH, '3', SXOR,
	PUSH,0x6c,PUSH, '3', SXOR,
	PUSH,0x4, PUSH, '3', SXOR,
	PUSH,0x0, PUSH, '4', SXOR,
	PUSH,0x7e,PUSH, '5', SXOR,
	PUSH,0x0, PUSH, '3', SXOR,
	PUSH,0x6c,PUSH, '3', SXOR,
	PUSH,0x7e,PUSH, '3', SXOR,
	PUSH,0x0, PUSH, '3', SXOR,
	PUSH,0x0, PUSH, '}', SXOR,
	EXIT
};

const int evaluate_check[] = {
  PUSH, 0xdeadface,
  PUSH, 0xdeadbeef,
  SUB,
  PUSH, 0xfeedface,
  ADD,
  PUSH, 0xfeee3174,
  SUB,
  ENTER,
  TEST,
  EXIT
};

void decoder(int instr, const int* code) {
	if (instr == PUSH) {
		if (full_sp()) {
			return;
		}

		sp++;
		stack[sp] = code[++ip];
		return;
	}
	if (instr == POP) {
		if (empty_sp()) {
			return;
		}
		int pop_value = stack[sp--];
		return;
	}
	if (instr == SXOR) {
		int a = stack[sp--];
		int b = stack[sp--];
		sp += 3;
		f_sp++;
		flag[f_sp] = a ^ b;
		return;
	}
	if (instr == ADD) {
		int a = stack[sp--];
		int b = stack[sp--];
		sp += 3;
		stack[sp] = b + a;
		return;
	}
	if (instr == SUB) {
		int a = stack[sp--];
		int b = stack[sp--];
		sp += 3;
		stack[sp] = b - a;
		return;
	}
	if (instr == DIV) {
		int a = stack[sp--];
		int b = stack[sp--];
		sp += 3;
		stack[sp] = b / a;
		return;
	}
	if (instr == MUL)
	{
		int a = stack[sp--];
		int b = stack[sp--];
		sp += 3;
		stack[sp] = b * a;
		return;
	}
	if (instr == RAM) {
		int x = sp;
		for (; x >= 0; --x) {
			printf("%u : 0x%x\n", x, stack[x]);
		}
		return;
	}
	if (instr == TEST) {
		int inp = stack[sp];
		if (stack[sp--] == inp) {
			int old_sp = sp;
			int old_ip = ip;
			sp = -1;
			ip = 0;
			while (VM) {
				decoder(generate_flag[ip], generate_flag);
				ip++;
			}
			VM = true;
			sp = old_sp;
			ip = old_ip;
			for (int i = 0; i < 46; i++) {
				std::cout << flag[i];
			}
			std::cout << std::endl;
		}
		else {
			char fake[] = "CATCHA_U_ARE_NOT_MY_SENPAII";
			for (int i = 0; i < 28; i++) {
				std::cout << fake[i];
			}
			std::cout << std::endl;
		}

		return;
	}
	if (instr == PRINT) {
		printf_s("%i : 0x%x\n", sp, stack[sp]);
		return;
	}
	if (instr == ENTER) {
		sp++;
		scanf_s("%i", &stack[sp]);
		return;
	}
	if (instr == EXIT)
	{
		VM = false;
		return;
	}
}

void dora_start() {
	std::string name, guess;
	bool rights = false;
	std::cout << "Hi! My name is D'RA, please prove me that you are my senpaii~ [^.^]" << std::endl << "Enter your name, pleaseeee~ [:3]" << std::endl << "> ";
	unsigned tired = 0;
	while (true) {
		std::cin.clear();
		std::getline(std::cin, name);

		if (name == "bye")
			break;

		++tired;

		if (name.empty())
			continue;

		if (name == "M4573R_53NP41") {
			rights = true;
		}

		if (tired > 2)
			std::cout << "If you're tired guessing my senpaii's name just say \"bye\"! [>.<]\nI've already noticed you are not him!!! [>.<]\"" << std::endl;

		if (!rights) {
			std::cout << "I can't talk to strangers! [>.>]" << std::endl;
			continue;
		}
		else {
			std::cout << "Oh senpaii u noticed me!" << std::endl << "Please say the magick phrase so i open my horn of plenty to you~" << std::endl << "> ";
			while (VM) {
				decoder(evaluate_check[ip], evaluate_check);
				ip++;
			}
			return;
		}


	}
	std::cout << "Bye secret stranger~\n";
}


int main() {
	dora_start();
}