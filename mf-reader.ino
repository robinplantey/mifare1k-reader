#include "Arduino.h"
#include <SPI.h>
#include <MFRC522.h>
#include <EDB.h>
#include <EEPROM.h>
#include "database.h"
#include <LiquidCrystal.h>
#include <CuteBuzzerSounds.h>


/////////////////////////////// MFRC522 /////////////////////////////// 
// Pins for the MFRC522
#define RST_PIN         3          
#define SS_PIN          2

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance


/////////////////////////////// EEPROM EDB /////////////////////////////// 
// EEPROM SIZE
#define TABLE_SIZE 1024

#define RECORDS_TO_CREATE 10

struct Users {
  byte id[4];
  byte keysA[16][6];
  byte keysB[16][6];
  byte token[48];
} 

Users;


// The read and write handlers for using the EEPROM Library
void writer(unsigned long address, byte data)
{
  EEPROM.write(address, data);
}

byte reader(unsigned long address)
{
  return EEPROM.read(address);
}

// Create an EDB object with the appropriate write and read handlers
EDB db(&writer, &reader);


/////////////////////////////// LCD DISPLAY /////////////////////////////// 

const int rs = 8, en = 9, d4 = 4, d5 = 5, d6 = 6, d7 = 7;
LiquidCrystal lcd(rs, en, d4, d5, d6, d7);


/////////////////////////////// BUZZER /////////////////////////////// 

#define BUZZER_PIN 10



/////////////////////////////////// Setup ///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

void setup() {
  Serial.begin(9600);           // Initialize serial communications with the PC
  SPI.begin();                                                  // Init SPI bus
  mfrc522.PCD_Init();                                           // Init MFRC522 card


// Create and fill database

  Serial.println();
  
  Serial.print("Initializing database...\n");
//   create table with starting address 0
  db.create(0, TABLE_SIZE, (unsigned int)sizeof(Users));

  for (int user=0; user < nbUser; user++){
  addUser(user, uidDB, keyADB, keyBDB, token);
  }
  Serial.println("Ready! \n");

// Initialize LCD display with number of columns and rows
lcd.begin(16, 2);


// Initialize Buzzer sounds
cute.init(BUZZER_PIN);  

}

/////////////////////////////////////////////////////////////////////////////////
///////////////////////////// Main loop /////////////////////////////////////////

void loop() {

  MFRC522::StatusCode status;
  
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }
  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }


int unlock = checkUID(mfrc522.uid.uidByte);

if (unlock > 0) {
  Serial.println("Authorized UID");
  Serial.println("Reading data blocks \n");


db.readRec(unlock, EDB_REC Users);
MFRC522::MIFARE_Key key;
  for (int i=0; i<6; i++) {
  key.keyByte[i] = Users.keysB[1][i];
  }

byte len = 18;
byte buffer[18];
byte token[48];
bool tokenCheck = true;

//Authenticate with sector 1 key B and read data block (48-byte token)
for (int block = 4; block<7; block++) {
   status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, &key, &(mfrc522.uid)); 
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }

  status = mfrc522.MIFARE_Read(block, buffer, &len);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Reading failed"));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }

  for (int i=0; i<16; i++) {
    if (Users.token[i+16*(block%4)] != buffer[i]) {
     tokenCheck = false;
     break;
    }
    if ( !tokenCheck) {
      break;
      }
    }
  
}

mfrc522.PCD_StopCrypto1(); 



if (tokenCheck && !mfrc522.MIFARE_OpenUidBackdoor(false)) {     //Unlock if the token is correct and the card is not gen1a UID-writable
  Serial.print("Unlocked!");
  lcd.print("Unlocked!");
  cute.play(S_CONNECTION);
  delay(3000);
  lcd.clear();
  return;
  }
 
 else {
  Serial.println("Access denied!");
  lcd.print("Access denied!");
  cute.play(S_OHOOH);
  delay(3000);
  lcd.clear();
  }
  }

else {
if (status == MFRC522::STATUS_OK) {
  Serial.println("Access denied!");
  lcd.print("Access denied!");
  cute.play(S_OHOOH);
  delay(3000);
  lcd.clear();
}

else {
  Serial.println("Error");
  lcd.print("Error");
  delay(1000);
  lcd.clear();
  }
}
}


/////////////////////////////// Utility functions for database queries /////////////////////////////// 

void recordLimit()
{
  Serial.print("Record Limit: ");
  Serial.println(db.limit());
}

void countRecords()
{
  Serial.print("Record Count: "); 
  Serial.println(db.count());
}

void addUser(int user, byte uidDB[nbUser][4], byte keyADB[nbUser][16][6], byte keyBDB[nbUser][16][6], byte token[nbUser][48])
{
  Serial.print("Adding authorized user with UID: ");
  for (int i=0 ; i<4; i++) {
  Users.id[i] = uidDB[user][i]; 
  Serial.print(uidDB[user][i], HEX);
  }
  for (int i=0; i<16; i++) {
    for (int j=0; j<6; j++) {
  Users.keysA[i][j] = keyADB[user][i][j];
  Users.keysB[i][j] = keyBDB[user][i][j];
  }
  }
  for (int i=0 ; i<48; i++) {
  Users.token[i] = token[user][i];
    }
  EDB_Status result = db.appendRec(EDB_REC Users);
  if (result != EDB_OK) printError(result);
  Serial.println("");
  Serial.println("Done.");
}

void deleteUser(int recno)
{
  Serial.print("Removing access for user with UID: ");
  
  EDB_Status result = db.readRec(recno, EDB_REC Users);
    if (result == EDB_OK)
    {
      int check = 0;
      for (int i=0; i<4; i++) {
      Serial.print(Users.id[i], HEX);
      }
  db.deleteRec(recno);
  Serial.println("");
  Serial.println("Done.");
}
}

void deleteAll()
{
  Serial.print("Removing access for all users!");
  db.clear();
  Serial.println("Done.");
}

int checkUID(byte uid[4])     //if uid is registered return record number in the user database
                              //otherwise return -1
{  
  for (int recno = 1; recno <= db.count(); recno++)
  {
    EDB_Status result = db.readRec(recno, EDB_REC Users);
    if (result == EDB_OK)
    {
      int check = 0;
      for (int i=0; i<4; i++) {
      if (Users.id[i] == uid[i]) {
        check ^= 1UL << i;
        }
      }
      if (check == 0b1111){
        return recno;
        }
 
    }
    else printError(result);
  }
  return -1;
}


void printError(EDB_Status err)
{
  Serial.print("ERROR: ");
  switch (err)
  {
    case EDB_OUT_OF_RANGE:
      Serial.println("Recno out of range");
      break;
    case EDB_TABLE_FULL:
      Serial.println("Table full");
      break;
    case EDB_OK:
    default:
      Serial.println("OK");
      break;
  }
}
