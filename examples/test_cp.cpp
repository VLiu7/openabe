/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
/// 
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
/// 
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
/// 
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \brief  Example use of the OpenABE API with CP-ABE
///

#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include<time.h>
#include <random>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {
  clock_t startTime,endTime;
  InitializeOpenABE();

  cout << "Testing CP-ABE context" << endl;

  OpenABECryptoContext cpabe("CP-ABE");

  string ct, pt3,pt1 = "C4UZBLx3Bn5SPsk8dlylwbhfKUcKa35vvZ1dCMPMgYepkcNrDsJzgYRfyzqfDQfKAMqskqOttutB6WmSlVH2atkpvslnmK6BYgGCXbHmFFP7YsuuO1793nuDEY1njLnTc8hd9BNPogN05fj3EGIZIr5AC2QNUXoj", pt2;
  cpabe.generateParams();

  cpabe.keygen("|attr1|attr2", "key0");

  int length=0;
  bool result;
  char tmp;
  for(int i=1;i<=10;i++){
    length=i*1000;
    pt3="";
    for (int i = 0; i < length; i++) {
      tmp = random() % 36;	// 随机一个小于 36 的整数，0-9、A-Z 共 36 种字符
      if (tmp < 10) {			// 如果随机数小于 10，变换成一个阿拉伯数字的 ASCII
        tmp += '0';
      } else {				// 否则，变换成一个大写字母的 ASCII
        tmp -= 10;
        tmp += 'A';
      }
      pt3 += tmp;
    }
    cout<<"string length:"<<pt3.length()<<endl;
    startTime = clock();
    cpabe.encrypt("attr1 and attr2", pt3, ct);
    endTime = clock();
    cout << "encrypt Time : " <<(double)(endTime - startTime)*1000/CLOCKS_PER_SEC << "ms" << endl;
    cout << "Ciphertext length:"<<ct.length()<<endl;
    startTime = clock();
    result = cpabe.decrypt("key0", ct, pt2);
    endTime = clock();
    cout << "decrypt  Time : " <<(double)(endTime - startTime)*1000/CLOCKS_PER_SEC  << "ms" << endl;

    assert(result && pt3 == pt2);

    //cout << "Recovered message: " << pt2 << endl;  
  }
  ShutdownOpenABE();

  return 0;
}
