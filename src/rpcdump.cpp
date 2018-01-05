// Copyright (c) 2009-2012 Bitcoin Developers
// Copyright (c) 2012-2013 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"

#include <boost/lexical_cast.hpp>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

#define printf OutputDebugStringF

// using namespace boost::asio;
using namespace json_spirit;
using namespace std;

extern Object JSONRPCError(int code, const string& message);

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

//#####Inicio de codigo agregado para importaddress
void ImportScript(const CScript& script, const std::string& strLabel, const CKeyID& AddID)
{
if (IsMine(*pwalletMain,script)) {
throw JSONRPCError(-4, "The wallet already contains this address or script");
}
int64_t nCreateTime = 1;
pwalletMain->MarkDirty();
if (!pwalletMain->AddWatchOnly(script, 1 /* nCreateTime */, AddID)) {
throw JSONRPCError(-4, "Error adding address to wallet");
}
pwalletMain->SetAddressBookName(AddID, strLabel);
}
Value importaddress(const Array& params, bool fHelp)
{
if (fHelp || params.size() < 1 || params.size() > 4)
throw std::runtime_error(
"importaddress \"address\" ( \"label\" rescan )\n"
"\nAdds a script (in hex) or address that can be watched as if it were in your wallet but cannot be used to spend.\n"
"\nArguments:\n"
"1. \"script\" (string, required) The hex-encoded script (or address)\n"
"2. \"label\" (string, optional, default=\"\") An optional label\n"
"3. rescan (boolean, optional, default=true) Rescan the wallet for transactions\n"
"\nNote: This call can take minutes to complete if rescan is true.\n"
"If you have the full public key, you should call importpubkey instead of this.\n"
"\nNote: If you import a non-standard raw script in hex form, outputs sending to it will be treated\n"
"as change, and not show up in many RPCs."
);
std::string strLabel = "";
if (params.size() > 1)
strLabel = params[1].get_str();
// Whether to perform rescan after import
bool fRescan = true;
if (params.size() > 2)
fRescan = params[2].get_bool();
LOCK2(cs_main, pwalletMain->cs_wallet);
CBitcoinAddress coinAdd;
coinAdd.SetString(params[0].get_str());
CKeyID dest;
if (coinAdd.IsValid() && coinAdd.GetKeyID(dest)) {
CScript scriptAdd;
scriptAdd.SetDestination(dest);
ImportScript(scriptAdd, strLabel, dest);
} else {
throw JSONRPCError(-4, "Invalid Leocoin address");
}
if (fRescan)
{
pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
pwalletMain->ReacceptWalletTransactions();
}
return Value::null;
}
//####Fin de codigo agregado para importaddress

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "importprivkey <lomocoinprivkey> [label]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();
    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(-5,"Invalid private key");
    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockMintOnly) // lomocoin: no importprivkey in mint-only mode
        throw JSONRPCError(-102, "Wallet is unlocked for minting only.");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(-4,"Error adding key to wallet");

        pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
        pwalletMain->ReacceptWalletTransactions();
    }

    MainFrameRepaint();

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <lomocoinaddress>\n"
            "Reveals the private key corresponding to <lomocoinaddress>.");

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(-5, "Invalid Lomocoin address");
    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockMintOnly) // lomocoin: no dumpprivkey in mint-only mode
        throw JSONRPCError(-102, "Wallet is unlocked for minting only.");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(-3, "Address does not refer to a key");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}

Value walletexport(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
    {
        throw runtime_error(
            "walletexport <destination> <passphrase>\n"
            "Export the wallet to <destination>.\n"
            "For encrypted wallet, enter <passphrase> same as the wallet passphrase.\n"
            "Otherwise, <passphrase> is new passphrase to import only.\n");
    }

    boost::filesystem::path pathDest(boost::filesystem::system_complete(params[0].get_str()));

    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[1].get_str().c_str();

    if (strWalletPass.length() < 1)
    {
        throw JSONRPCError(-13,"Invalid passphrase");
    }

    if (!pwalletMain->Export(pathDest,strWalletPass))
    {
        throw JSONRPCError(-102,"Failed to export wallet");
    }
    return Value::null;
}

