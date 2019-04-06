// ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
// 
// [Bitcoin Firewall 2.0.0
// March, 2019 - Biznatch Enterprises & Profit Hunters Coin (PHC)
// https://github.com/BiznatchEnterprises/BitcoinFirewall
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcserver.h"
#include "main.h"
#include "net.h"
#include "kernel.h"
#include "checkpoints.h"
#include "init.h"
#include "firewall.h"

using namespace json_spirit;
using namespace std;
using namespace CBan;

#include <boost/foreach.hpp>
#include "json/json_spirit_value.h"


extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);


Value firewallstatus(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("firewallstatus \"\n"
                            "\nGet the status of Bitcoin Firewall.\n"
        );
    }

    Object result;
    result.push_back(Pair("enabled",                            BoolToString(Firewall::Enabled)));
    result.push_back(Pair("blacklist-clear",                    BoolToString(Firewall::Blacklist_Autoclear)));
    result.push_back(Pair("banlist-clear",                      BoolToString(Firewall::Bans_Autoclear)));
    result.push_back(Pair("livedebug-detect",                   BoolToString(Firewall::LiveDebug_Enabled)));
    result.push_back(Pair("livedebug-exam",                     BoolToString(Firewall::LiveDebug_Exam)));
    result.push_back(Pair("livedebug-bans",                     BoolToString(Firewall::LiveDebug_Bans)));
    result.push_back(Pair("livedebug-blacklist",                BoolToString(Firewall::LiveDebug_Blacklist)));
    result.push_back(Pair("livedebug-disconnect",               BoolToString(Firewall::LiveDebug_Disconnect)));
    result.push_back(Pair("livedebug-bandwidthabuse",           BoolToString(Firewall::LiveDebug_BandwidthAbuse)));
    result.push_back(Pair("livedebug-nofalsepositive",          BoolToString(Firewall::LiveDebug_Nofalsepositive)));
    result.push_back(Pair("livedebug-invalidwallet",            BoolToString(Firewall::LiveDebug_InvalidWallet)));
    result.push_back(Pair("livedebug-forkedwallet",             BoolToString(Firewall::LiveDebug_ForkedWallet)));
    result.push_back(Pair("livedebug-floodingwallet",           BoolToString(Firewall::LiveDebug_FloodingWallet)));
    result.push_back(Pair("bandwidthabuse-detect",              BoolToString(Firewall::BandwidthAbuse_Detect)));
    result.push_back(Pair("bandwidthabuse-nofalsepositive",     BoolToString(Firewall::BandwidthAbuse_Nofalsepositive)));
    result.push_back(Pair("bandwidthabuse-blacklist",           BoolToString(Firewall::BandwidthAbuse_Blacklist)));
    result.push_back(Pair("bandwidthabuse-bantime",             (int64_t)Firewall::BandwidthAbuse_BanTime));
    result.push_back(Pair("bandwidthabuse-ban",                 BoolToString(Firewall::BandwidthAbuse_Ban)));
    result.push_back(Pair("invalidwallet-detect",               BoolToString(Firewall::InvalidWallet_Detect)));
    result.push_back(Pair("invalidwallet-blacklist",            BoolToString(Firewall::InvalidWallet_Blacklist)));
    result.push_back(Pair("invalidwallet-ban",                  BoolToString(Firewall::InvalidWallet_Ban)));
    result.push_back(Pair("invalidwallet-bantime",              (int64_t)Firewall::InvalidWallet_BanTime));
    result.push_back(Pair("floodingwallet-detect",              BoolToString(Firewall::FloodingWallet_Detect)));
    result.push_back(Pair("floodingwallet-blacklist",           BoolToString(Firewall::FloodingWallet_Blacklist)));
    result.push_back(Pair("floodingwallet-ban",                 BoolToString(Firewall::FloodingWallet_Ban)));
    result.push_back(Pair("floodingwallet-bantime",             (int64_t)Firewall::FloodingWallet_BanTime));
    result.push_back(Pair("forkedwallet-detect",                BoolToString(Firewall::ForkedWallet_Detect)));
    result.push_back(Pair("forkedwallet-blacklist",             BoolToString(Firewall::ForkedWallet_Blacklist)));
    result.push_back(Pair("forkedwallet-ban",                   BoolToString(Firewall::ForkedWallet_Ban)));
    result.push_back(Pair("forkedwallet-bantime",               (int64_t)Firewall::ForkedWallet_BanTime));

    return result;
}


Value firewallenabled(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallenabled \"true|false\"\n"
                            "\nChange the status of Bitcoin Firewall.\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewallenabled", "true")
                            + HelpExampleCli("firewallenabled", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::Enabled = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("enabled", Firewall::Enabled));

    return result;
}


Value firewallclearblacklist(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallclearblacklist \"true|false\"\n"
                            "\nBitcoin Firewall Clear Blacklist (session)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - false\n"
                            + HelpExampleCli("firewallclearblacklist", "true")
                            + HelpExampleCli("firewallclearblacklist", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::Blacklist_Autoclear = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("clear-blacklist", Firewall::Blacklist_Autoclear));

    return result;
}


Value firewallclearbanlist(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error(
                            "firewallclearbanlist \"true|false\"\n"
                            "\nBitcoin Firewall Clear Ban List (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - false\n"
                            + HelpExampleCli("firewallclearbanlist", "true")
                            + HelpExampleCli("firewallclearbanlist", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::Bans_Autoclear = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("clear-banlist", Firewall::Bans_Autoclear));

    return result;
}


Value getpeeraverageheight(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw runtime_error("getpeeraverageheight\n"
                            "Returns average blockheight among connected nodes.");
    }
   
    return Firewall::AverageHeight;
}


Value firewalldebug(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebug \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - false\n"
                            + HelpExampleCli("firewalldebug", "true")
                            + HelpExampleCli("firewalldebug", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_Enabled = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug", Firewall::LiveDebug_Enabled));

    return result;
}


Value firewalldebugexam(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugexam \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Exam\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugexam", "true")
                            + HelpExampleCli("firewalldebugexam", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_Exam = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-exam", Firewall::LiveDebug_Exam));

    return result;
}


Value firewalldebugbans(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugbans \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Bans\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugbans", "true")
                            + HelpExampleCli("firewalldebugbans", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_Bans = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-bans", Firewall::LiveDebug_Bans));

    return result;
}


Value firewalldebugblacklist(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugblacklist \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Blacklist\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugblacklist", "true")
                            + HelpExampleCli("firewalldebugblacklist", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_Blacklist = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-blacklist", Firewall::LiveDebug_Blacklist));

    return result;
}


Value firewalldebugdisconnect(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugdisconnect \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Disconnect\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugdisconnect", "true")
                            + HelpExampleCli("firewalldebugdisconnect", "false")
                            );
    }


    if (params.size() == 1)
    {
        Firewall::LiveDebug_Disconnect = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-disconnect", Firewall::LiveDebug_Disconnect));

    return result;
}


Value firewalldebugbandwidthabuse(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugbandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Bandwidth Abuse\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugbandwidthabuse", "true")
                            + HelpExampleCli("firewalldebugbandwidthabuse", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_BandwidthAbuse = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-bandwidthabuse", Firewall::LiveDebug_BandwidthAbuse));

    return result;
}


Value firewalldebugnofalsepositivebandwidthabuse(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugnofalsepositivebandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - No False Positive (Bandwidth Abuse)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugnofalsepositivebandwidthabuse", "true")
                            + HelpExampleCli("firewalldebugnofalsepositivebandwidthabuse", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_Nofalsepositive = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-nofalsepositive", Firewall::LiveDebug_Nofalsepositive));

    return result;
}


Value firewalldebuginvalidwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebuginvalidwallet \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Invalid Wallet\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebuginvalidwallet", "true")
                            + HelpExampleCli("firewalldebuginvalidwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_InvalidWallet = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-invalidwallet", Firewall::LiveDebug_InvalidWallet));

    return result;
}


Value firewalldebugforkedwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugforkedwallet \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Forked Wallet\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - true\n"
                            + HelpExampleCli("firewalldebugforkedwallet", "true")
                            + HelpExampleCli("firewalldebugforkedwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_ForkedWallet = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-forkedwallet", Firewall::LiveDebug_ForkedWallet));

    return result;
}


Value firewalldebugfloodingwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldebugfloodingwallet \"true|false\"\n"
                            "\nBitcoin Firewall Live Debug Output - Flooding Wallet\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldebugfloodingwallet", "true")
                            + HelpExampleCli("firewalldebugfloodingwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::LiveDebug_FloodingWallet = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("live-debug-floodingwallet", Firewall::LiveDebug_FloodingWallet));

    return result;
}


Value firewallaveragetolerance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallaveragetolerance \"tolerance\"\n"
                            "\nBitcoin Firewall Exam Setting (Average Block Tolerance)\n"
                            "\nArguments:\n"
                            "Value: \"tolerance\" (double, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallaveragetolerance", "0.0001")
                            + HelpExampleCli("firewallaveragetolerance", "0.1")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::Average_Tolerance = strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("exam-average-tolerance", Firewall::Average_Tolerance));

    return result;
}


Value firewallaveragerange(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallaveragerange \"zone\"\n"
                            "\nBitcoin Firewall Exam Setting (Average Block Range)\n"
                            "\nArguments:\n"
                            "Value: \"zone\" (integer), required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallaveragerange", "10")
                            + HelpExampleCli("firewallaveragerange", "50")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::Average_Range = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("exam-average-range", Firewall::Average_Range));

    return result;
}


Value firewalltraffictolerance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalltraffictolerance \"tolerance\"\n"
                            "\nBitcoin Firewall Exam Setting (Traffic Tolerance)\n"
                            "\nArguments:\n"
                            "Value: \"tolerance\" (double, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalltraffictolerance", "0.0001")
                            + HelpExampleCli("firewalltraffictolerance", "0.1")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::Traffic_Tolerance = strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("exam-traffic-tolerance", Firewall::Traffic_Tolerance));

    return result;
}


Value firewalltrafficzone(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalltrafficzone \"zone\"\n"
                            "\nBitcoin Firewall Exam Setting (Traffic Zone)\n"
                            "\nArguments:\n"
                            "Value: \"zone\" (double), required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalltrafficzone", "10.10")
                            + HelpExampleCli("firewalltrafficzone", "50.50")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::Traffic_Zone = strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("exam-traffic-zone", Firewall::Traffic_Zone));

    return result;
}


Value firewalladdtowhitelist(const Array& params, bool fHelp)
{
    // TODO: Upgrade to std::list<std::string>   Firewall::WhiteList.push_back() 

    string MSG;

    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalladdtowhitelist \"address\"\n"
                            "\nBitcoin Firewall Adds IP Address to General Rule\n"
                            "\nArguments:\n"
                            "Value: \"address\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewalladdtowhitelist", "IP")
                            + HelpExampleCli("firewalladdtowhitelist", "127.0.0.1")
                            );
    }

    if (params.size() == 1)
    {
        if (CountStringArray(Firewall::WhiteList) < 256)
        {
            Firewall::WhiteList[CountStringArray(Firewall::WhiteList)] = params[0].get_str();
            MSG = CountStringArray(Firewall::WhiteList);
        }
        else
        {
            MSG = "Over 256 Max!";
        }
    }

    Object result;
    result.push_back(Pair("exam-whitelist-add", MSG));

    return result;
}


Value firewalladdtoblacklist(const Array& params, bool fHelp)
{
    // TODO: Upgrade to std::list<std::string>   Firewall::BlackList.push_back() 

    string MSG;

    if (fHelp || params.size() == 0)
        throw runtime_error(
                            "firewalladdtoblacklist \"address\"\n"
                            "\nBitcoin Firewall Adds IP Address to General Rule\n"
                            "\nArguments:\n"
                            "Value: \"address\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewalladdtoblacklist", "IP")
                            + HelpExampleCli("firewalladdtoblacklist", "127.0.0.1")
                            );

    if (params.size() == 1)
    {
        if (CountStringArray(Firewall::BlackList) < 256)
        {
            Firewall::BlackList[CountStringArray(Firewall::BlackList)] = params[0].get_str();
            MSG = CountStringArray(Firewall::BlackList);
        }
        else
        {
            MSG = "Over 256 Max!";
        }
    }

    Object result;
    result.push_back(Pair("exam-blacklist-add", MSG));

    return result;
}


Value firewalldetectbandwidthabuse(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldetectbandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Detect Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectbandwidthabuse", "true")
                            + HelpExampleCli("firewalldetectbandwidthabuse", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_Detect = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("detect-bandwidthabuse", Firewall::BandwidthAbuse_Detect));

    return result;
}


Value firewallblacklistbandwidthabuse(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallblacklistbandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Blacklist Bandwidth Abuse Rule #1 (session)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallblacklistbandwidthabuse", "true")
                            + HelpExampleCli("firewallblacklistbandwidthabuse", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_Blacklist = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("blacklist-bandwidthabuse", Firewall::BandwidthAbuse_Blacklist));

    return result;
}


Value firewallbanbandwidthabuse(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbanbandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall Ban Bandwidth Abuse Rule #1 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbanbandwidthabuse", "true")
                            + HelpExampleCli("firewallbanbandwidthabuse", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_Ban = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("ban-bandwidthabuse", Firewall::BandwidthAbuse_Ban));

    return result;
}


Value firewallnofalsepositivebandwidthabuse(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallnofalsepositivebandwidthabuse \"true|false\"\n"
                            "\nBitcoin Firewall False Positive Protection Rule #1\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallnofalsepositivebandwidthabuse", "true")
                            + HelpExampleCli("firewallnofalsepositivebandwidthabuse", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_Nofalsepositive = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("firewallnofalsepositivebandwidthabuse", Firewall::BandwidthAbuse_Nofalsepositive));

    return result;
}


Value firewallbantimebandwidthabuse(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbantimebandwidthabuse \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Value: \"0|10000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimebandwidthabuse", "0")
                            + HelpExampleCli("firewallbantimebandwidthabuse", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_BanTime = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("bantime-bandwidthabuse", Firewall::BandwidthAbuse_BanTime));

    return result;
}


Value firewallbandwidthabusemaxcheck(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbandwidthabusemaxcheck \"seconds\"\n"
                            "\nBitcoin Firewall Max Check Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Seconds: \"0|10000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default\n"
                            + HelpExampleCli("firewallbandwidthabusemaxcheck", "0")
                            + HelpExampleCli("firewallbandwidthabusemaxcheck", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_Maxcheck = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("maxcheck-bandwidthabuse", Firewall::BandwidthAbuse_Maxcheck));

    return result;
}


Value firewallbandwidthabuseminattack(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbandwidthabuseminattack \"value\"\n"
                            "\nBitcoin Firewall Min Attack Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Value: \"17.1\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 17.1\n"
                            + HelpExampleCli("firewallbandwidthabuseminattack", "17.1")
                            + HelpExampleCli("firewallbandwidthabuseminattack", "17.005")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_MinAttack = strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("minattack-bandwidthabuse", Firewall::BandwidthAbuse_MinAttack));

    return result;
}


Value firewallbandwidthabusemaxattack(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbandwidthabusemaxattack \"ratio\"\n"
                            "\nBitcoin Firewall Max Attack Bandwidth Abuse Rule #1\n"
                            "\nArguments:\n"
                            "Value: \"17.2\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 17.2\n"
                            + HelpExampleCli("firewallbandwidthabusemaxattack", "17.2")
                            + HelpExampleCli("firewallbandwidthabusemaxattack", "18.004")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::BandwidthAbuse_MaxAttack = strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("maxattack-bandwidthabuse", Firewall::BandwidthAbuse_MaxAttack));

    return result;
}


Value firewalldetectinvalidwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldetectinvalidwallet \"true|false\"\n"
                            "\nBitcoin Firewall Detect Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectinvalidwallet", "true")
                            + HelpExampleCli("firewalldetectinvalidwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::InvalidWallet_Detect = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("detect-invalidwallet", Firewall::InvalidWallet_Detect));

    return result;
}


Value firewallblacklistinvalidwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallblacklistinvalidwallet \"true|false\"\n"
                            "\nBitcoin Firewall Blacklist Invalid Wallet Rule #2 (session)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallblacklistinvalidwallet", "true")
                            + HelpExampleCli("firewallblacklistinvalidwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::InvalidWallet_Blacklist = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("blacklist-invalidwallet", Firewall::InvalidWallet_Blacklist));

    return result;
}


Value firewallbaninvalidwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbaninvalidwallet \"true|false\"\n"
                            "\nBitcoin Firewall Ban Invalid Wallet Rule #2 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbaninvalidwallet", "true")
                            + HelpExampleCli("firewallbaninvalidwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::InvalidWallet_Ban = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("ban-invalidwallet", Firewall::InvalidWallet_Ban));

    return result;
}


Value firewallbantimeinvalidwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbantimeinvalidwallet \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Value: \"0|100000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimeinvalidwallet", "0")
                            + HelpExampleCli("firewallbantimeinvalidwallet", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::InvalidWallet_BanTime = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("bantime-invalidwallet", Firewall::InvalidWallet_BanTime));

    return result;
}


Value firewallinvalidwalletminprotocol(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallinvalidwalletminprotocol \"protocol\"\n"
                            "\nBitcoin Firewall Min Protocol Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Value: \"0|100000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallinvalidwalletminprotocol", "0")
                            + HelpExampleCli("firewallinvalidwalletminprotocol", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::InvalidWallet_MinimumProtocol = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("minprotocol-invalidwallet", Firewall::InvalidWallet_MinimumProtocol));

    return result;
}


Value firewallinvalidwalletmaxcheck(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallinvalidwalletmaxcheck \"seconds\"\n"
                            "\nBitcoin Firewall Max Check Invalid Wallet Rule #2\n"
                            "\nArguments:\n"
                            "Value: \"0|100000\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallinvalidwalletmaxcheck", "0")
                            + HelpExampleCli("firewallinvalidwalletmaxcheck", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::InvalidWallet_MaxCheck = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("maxcheck-invalidwallet", Firewall::InvalidWallet_MaxCheck));

    return result;
}


Value firewalldetectforkedwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldetectforkedwallet \"true|false\"\n"
                            "\nBitcoin Firewall Detect Forked Wallet Rule #3\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectforkedwallet", "true")
                            + HelpExampleCli("firewalldetectforkedwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::ForkedWallet_Detect = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("detect-forkedwallet", Firewall::ForkedWallet_Detect));

    return result;
}


Value firewallblacklistforkedwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallblacklistforkedwallet \"true|false\"\n"
                            "\nBitcoin Firewall Blacklist Forked Wallet Rule #3 (session)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallblacklistforkedwallet", "true")
                            + HelpExampleCli("firewallblacklistforkedwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::ForkedWallet_Blacklist = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("blacklist-forkedwallet", Firewall::ForkedWallet_Blacklist));

    return result;
}


Value firewallbanforkedwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbanforkedwallet \"true|false\"\n"
                            "\nBitcoin Firewall Ban Forked Wallet Rule #3 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbanforkedwallet", "true")
                            + HelpExampleCli("firewallbanforkedwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::ForkedWallet_Ban = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("ban-forkedwallet", Firewall::ForkedWallet_Ban));

    return result;
}


Value firewallbantimeforkedwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbantimeforkedwallet \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Forked Wallet Rule #3\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimeinvalidwallet", "0")
                            + HelpExampleCli("firewallbantimeinvalidwallet", "10000000")
                            );
    }

    if (params.size() == 1)
    {
         Firewall::ForkedWallet_BanTime = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("bantime-forkedwallet", Firewall::ForkedWallet_BanTime));

    return result;
}


Value firewallforkedwalletnodeheight(const Array& params, bool fHelp)
{
    // TODO: Upgrade to std::list<std::string> std::list<int>   FIREWALL_FORKED_NODEHEIGHT.push_back() 

    string MSG;

    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallforkedwalletnodeheight \"blockheight\"\n"
                            "\nBitcoin Firewall Adds Forked NodeHeight Flooding Wallet Rule #3\n"
                            "\nArguments:\n"
                            "Value: \"blockheight\" (int, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallforkedwalletnodeheight", "0")
                            + HelpExampleCli("firewallforkedwalletnodeheight", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        if (CountIntArray(Firewall::ForkedWallet_NodeHeight) < 256)
        {
            Firewall::ForkedWallet_NodeHeight[CountIntArray(Firewall::ForkedWallet_NodeHeight)] = (int)strtod(params[0].get_str().c_str(), NULL);
            MSG = CountIntArray(Firewall::ForkedWallet_NodeHeight);
        }
        else
        {
            MSG = "Over 256 Max!";
        }
    }

    Object result;
    result.push_back(Pair("attackpattern-forkedwallet-nodeheight-add", MSG));

    return result;
}


Value firewalldetectfloodingwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewalldetectfloodingwallet \"true|false\"\n"
                            "\nBitcoin Firewall Detect Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewalldetectfloodingwallet", "true")
                            + HelpExampleCli("firewalldetectfloodingwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_Detect = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("detect-floodingwallet", Firewall::FloodingWallet_Detect));

    return result;
}


Value firewallblacklistfloodingwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallblacklistfloodingwallet \"true|false\"\n"
                            "\nBitcoin Firewall Blacklist Flooding Wallet Rule #4 (session)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallblacklistfloodingwallet", "true")
                            + HelpExampleCli("firewallblacklistfloodingwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_Blacklist = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("blacklist-floodingwallet", Firewall::FloodingWallet_Blacklist));

    return result;
}


Value firewallbanfloodingwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbanfloodingwallet \"true|false\"\n"
                            "\nBitcoin Firewall Ban Flooding Wallet Rule #4 (permenant)\n"
                            "\nArguments:\n"
                            "Status: \"true|false\" (bool, required)\n"
                            "\nExamples:\n"
                            + HelpExampleCli("firewallbanfloodingwallet", "true")
                            + HelpExampleCli("firewallbanfloodingwallet", "false")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_Ban = StringToBool(params[0].get_str());
    }

    Object result;
    result.push_back(Pair("ban-floodingwallet", Firewall::FloodingWallet_Ban));

    return result;
}


Value firewallbantimefloodingwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbantimefloodingwallet \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 24h\n"
                            + HelpExampleCli("firewallbantimefloodingwallet", "0")
                            + HelpExampleCli("firewallbantimefloodingwallet", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_BanTime = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("bantime-floodingwallet", Firewall::FloodingWallet_BanTime));

    return result;
}


Value firewallfloodingwalletminbytes(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletminbytes \"bytes\"\n"
                            "\nBitcoin Firewall Min Bytes Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"Bytes\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - h\n"
                            + HelpExampleCli("firewallfloodingwalletminbytes", "0")
                            + HelpExampleCli("firewallfloodingwalletminbytes", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_MinBytes = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("minbytes-floodingwallet", Firewall::FloodingWallet_MinBytes));

    return result;
}


Value firewallfloodingwalletmaxbytes(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletmaxbytes \"bytes\"\n"
                            "\nBitcoin Firewall Max Bytes Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"bytes\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmaxbytes", "0")
                            + HelpExampleCli("firewallfloodingwalletmaxbytes", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_MaxBytes = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("bantime-floodingwallet", Firewall::FloodingWallet_MaxBytes));

    return result;
}


Value firewallfloodingwalletattackpatternadd(const Array& params, bool fHelp)
{
    // TODO: Upgrade to vector<string> 
    
    string MSG;

    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletattackpatternadd \"warnings\"\n"
                            "\nBitcoin Firewall Adds Attack Pattern Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"warnings\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletattackpatternadd", "0")
                            + HelpExampleCli("firewallfloodingwalletattackpatternadd", "10000000")
                            );
    }

    MSG = "OK!";

    if (params.size() == 1)
    {
        if (CountStringArray(Firewall::FloodingWallet_Patterns) < 256)
        {
            Firewall::FloodingWallet_Patterns[CountStringArray(Firewall::FloodingWallet_Patterns)] = params[0].get_str().c_str();
            MSG = Firewall::FloodingWallet_Patterns[CountStringArray(Firewall::FloodingWallet_Patterns)];
        }
        else
        {
            MSG = "Over 256 Max!";
        }
    }

    Object result;
    result.push_back(Pair("floodingwallet-attackpattern-add", strprintf("%s %d (%s)", params[0].get_str().c_str(), CountStringArray(Firewall::FloodingWallet_Patterns), MSG)));

    return result;
}


Value firewallfloodingwalletattackpatternremove(const Array& params, bool fHelp)
{
    // TODO: Upgrade to vector<string> Firewall::FloodingWallet_Patterns 

    string MSG;
    int i;

    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletattackpatternremove \"warnings\"\n"
                            "\nBitcoin Firewall Remove Attack Pattern Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"warnings\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletattackpatternremove", "0")
                            + HelpExampleCli("firewallfloodingwalletattackpatternremove", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        string WARNING;

        int TmpFloodPatternsCount;
        
        WARNING = params[0].get_str().c_str();
        
        TmpFloodPatternsCount = CountStringArray(Firewall::FloodingWallet_Patterns);

        MSG = "Not Found";

        for (i = 0; i < TmpFloodPatternsCount; i++)
        {  
            if (WARNING == Firewall::FloodingWallet_Patterns[i])
            {
                MSG = i;
                Firewall::FloodingWallet_Patterns[i] = "";
            }
        }
    }

    Object result;
    result.push_back(Pair("floodingwallet-attackpattern-remove", strprintf("%s %d (%s)", params[0].get_str().c_str(), CountStringArray(Firewall::FloodingWallet_Patterns), MSG)));

    return result;
}



Value firewallfloodingwalletattackignoredadd(const Array& params, bool fHelp)
{
    // TODO: Upgrade to vector<string> 
    
    string MSG;

    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletattackignoredadd \"warnings\"\n"
                            "\nBitcoin Firewall Adds Attack Ignored Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"warnings\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletattackignoredadd", "0")
                            + HelpExampleCli("firewallfloodingwalletattackignoredadd", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        MSG = "Ok!";

        if (CountStringArray(Firewall::FloodingWallet_Ignored) < 256)
        {
            Firewall::FloodingWallet_Ignored[CountStringArray(Firewall::FloodingWallet_Ignored)] = params[0].get_str().c_str();
            MSG = Firewall::FloodingWallet_Ignored[CountStringArray(Firewall::FloodingWallet_Ignored)];
        }
        else
        {
            MSG = "Over 256 Max!";
        }
    }

    Object result;
    result.push_back(Pair("floodingwallet-attackignored-add", strprintf("%s %d (%s)", params[0].get_str().c_str(), CountStringArray(Firewall::FloodingWallet_Patterns), MSG)));

    return result;
}


Value firewallfloodingwalletattackignoredremove(const Array& params, bool fHelp)
{
    // TODO: Upgrade to vector<string> Firewall::FloodingWallet_remove

    string MSG;
    int i;

    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletattackignoredremove \"warnings\"\n"
                            "\nBitcoin Firewall Remove Attack Ignored Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"warnings\" (string, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletattackignoredremove", "0")
                            + HelpExampleCli("firewallfloodingwalletattackignoredremove", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        string WARNING;

        int TmpFloodIgnoredCount;
        
        WARNING = params[0].get_str().c_str();
        
        TmpFloodIgnoredCount = CountStringArray(Firewall::FloodingWallet_Ignored);

        MSG = "Not Found";

        for (i = 0; i < TmpFloodIgnoredCount; i++)
        {  
            if (WARNING == Firewall::FloodingWallet_Ignored[i])
            {
                MSG = i;
                Firewall::FloodingWallet_Ignored[i] = "";
            }
        }
    }

    Object result;
    result.push_back(Pair("floodingwallet-attackignored-remove", strprintf("%s %d (%s)", params[0].get_str().c_str(), CountStringArray(Firewall::FloodingWallet_Patterns), MSG)));

    return result;
}


Value firewallfloodingwalletmintrafficavg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletmintrafficavg \"ratio\"\n"
                            "\nBitcoin Firewall Min Traffic Average Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"ratio\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - 2000\n"
                            + HelpExampleCli("firewallfloodingwalletmintrafficav", "20000.01")
                            + HelpExampleCli("firewallfloodingwalletmintrafficav", "12000.014")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_MinTrafficAverage = strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("mintrafficavg-floodingwallet", Firewall::FloodingWallet_MinTrafficAverage));

    return result;
}


Value firewallfloodingwalletmaxtrafficavg(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallbantimefloodingwallet \"ratio\"\n"
                            "\nBitcoin Firewall Max Traffic Average Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"ratio\" (double, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmaxtrafficavg", "100.10")
                            + HelpExampleCli("ffirewallfloodingwalletmaxtrafficavg", "10.8")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_MaxTrafficAverage = strtod(params[0].get_str().c_str(), NULL);;
    }

    Object result;
    result.push_back(Pair("trafficavg-floodingwallet", Firewall::FloodingWallet_MaxTrafficAverage));

    return result;
}


Value firewallfloodingwalletmincheck(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletmincheck \"seconds\"\n"
                            "\nBitcoin Firewall Ban Time Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmincheck", "0")
                            + HelpExampleCli("firewallfloodingwalletmincheck", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_MinCheck = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("mincheck-floodingwallet", Firewall::FloodingWallet_MinCheck));

    return result;
}


Value firewallfloodingwalletmaxcheck(const Array& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
    {
        throw runtime_error("firewallfloodingwalletmaxcheck \"seconds\"\n"
                            "\nBitcoin Firewall Max Check Flooding Wallet Rule #4\n"
                            "\nArguments:\n"
                            "Value: \"seconds\" (integer, required)\n"
                            "\nExamples:\n"
                            "\n0 = default - \n"
                            + HelpExampleCli("firewallfloodingwalletmaxcheck", "0")
                            + HelpExampleCli("firewallfloodingwalletmaxcheck", "10000000")
                            );
    }

    if (params.size() == 1)
    {
        Firewall::FloodingWallet_MaxCheck = (int)strtod(params[0].get_str().c_str(), NULL);
    }

    Object result;
    result.push_back(Pair("maxcheck-floodingwallet", Firewall::FloodingWallet_MaxCheck));

    return result;
}


// |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||