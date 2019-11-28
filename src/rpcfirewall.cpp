/*
    ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
    ||||                                                                                            ||||
    |||| Bitcoin Firewall 2.0.0.4 (Oct, 2019)                                                       ||||
    ||||                                                                                            ||||
    |||| Copyright (c) 2016 Biznatch Enterprises                                                    ||||
    |||| Copyright (c) 2017 BATA Development                                                        ||||
    |||| Copyright (c) 2018-2019 Profit Hunters Coin                                                ||||
    ||||                                                                                            ||||
    |||| https://github.com/BiznatchEnterprises/BitcoinFirewall                                     ||||
    ||||                                                                                            ||||
    |||| Distributed under the MIT/X11 software license, see the accompanying                       ||||
    |||| file COPYING or http://www.opensource.org/licenses/mit-license.php.                        ||||
    ||||                                                                                            ||||
    ||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
*/


#include "rpcserver.h"
#include "main.h"
#include "net.h"
#include "kernel.h"
#include "checkpoints.h"
#include "init.h"
#include "firewall.h"

#include "json/json_spirit_value.h"


using namespace json_spirit;
using namespace std;
using namespace CBan;
using namespace Firewall;


extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);


/*

firewall <command> <argument>

*/



Value firewall(const Array& params, bool fHelp)
{   
    Object result;

    std::string MSG;
    std::string strSubCommand;
    std::string strArgument1;
    std::string strArgument2;

    if (params.size() >= 1)
    {
        strSubCommand = params[0].get_str();
    }

    if (params.size() >= 2)
    {
    	strArgument1 = params[1].get_str().c_str();
    }

    if (params.size() >= 3)
    {
    	strArgument2 = params[2].get_str().c_str();
    }

    if (fHelp 
        ||
        (
            strSubCommand != "getstatus" &&
            strSubCommand != "setstatus" &&
            strSubCommand != "getinfo" &&
            strSubCommand != "cleardenied" &&
            strSubCommand != "clearbanned" &&
            strSubCommand != "getpeeraverageheight" &&
            strSubCommand != "debug:enabled" &&
            strSubCommand != "debug:exam" &&
            strSubCommand != "debug:bans" &&
            strSubCommand != "debug:denied" &&
            strSubCommand != "debug:disconnect" &&
            strSubCommand != "debug:doublespend" &&
            strSubCommand != "debug:invalidwallet" &&
            strSubCommand != "debug:forkedwallet " &&
            strSubCommand != "debug:floodingwallet " &&
            strSubCommand != "debug:ddoswallet " &&
            strSubCommand != "debug:eclipsewallet" &&
            strSubCommand != "debug:erebuswallet" &&
            strSubCommand != "debug:bgpwallet" &&
            strSubCommand != "debug:resetsyncwallet" &&
            strSubCommand != "averagetolerance" &&
            strSubCommand != "averagerange" &&
            strSubCommand != "traffictolerance" &&
            strSubCommand != "trafficzone" &&
            strSubCommand != "addtoallowed" &&
            strSubCommand != "addtodenied" &&
            strSubCommand != "bandwidthabuse:detect" &&
            strSubCommand != "bandwidthabuse:denied" &&
            strSubCommand != "bandwidthabuse:ban" &&
            strSubCommand != "bandwidthabuse:bantime" &&
            strSubCommand != "bandwidthabuse:disconnect" &&
            strSubCommand != "bandwidthabuse:mincheck" &&
            strSubCommand != "doublespend:detect" &&
            strSubCommand != "doublespend:denied" &&
            strSubCommand != "doublespend:ban" &&
            strSubCommand != "doublespend:bantime" &&
            strSubCommand != "doublespend:disconnect" &&
            strSubCommand != "doublespend:mincheck" &&
            strSubCommand != "doublespend:minattack" &&
            strSubCommand != "doublespend:maxattack" &&
            strSubCommand != "invalidwallet:detect" &&
            strSubCommand != "invalidwallet:denied" &&
            strSubCommand != "invalidwallet:ban" &&
            strSubCommand != "invalidwallet:bantime" &&
            strSubCommand != "invalidwallet:disconnect" &&
            strSubCommand != "invalidwallet:minprotocol" &&
            strSubCommand != "invalidwallet:mincheck" &&
            strSubCommand != "forkedwallet:detect" &&
            strSubCommand != "forkedwallet:denied" &&
            strSubCommand != "forkedwallet:ban" &&
            strSubCommand != "forkedwallet:bantime" &&
            strSubCommand != "forkedwallet:disconnect" &&
            strSubCommand != "forkedwallet:mincheck" &&
            strSubCommand != "forkedwallet:nodeheight" &&
            strSubCommand != "floodingwallet:detect" &&
            strSubCommand != "floodingwallet:denied" &&
            strSubCommand != "floodingwallet:ban" &&
            strSubCommand != "floodingwallet:bantime" &&
            strSubCommand != "floodingwallet:disconnect" &&
            strSubCommand != "floodingwallet:mincheck" &&
            strSubCommand != "floodingwallet:minbytes" &&
            strSubCommand != "floodingwallet:maxbytes" &&
            strSubCommand != "floodingwallet:attackpattern:add" &&
            strSubCommand != "floodingwallet:attackpattern:remove" &&
            strSubCommand != "floodingwallet:attackignored:add" &&
            strSubCommand != "floodingwallet:attackignored:remove" &&
            strSubCommand != "floodingwallet:mintrafficavg" &&
            strSubCommand != "floodingwallet:maxtrafficavg" &&
            strSubCommand != "floodingwallet:mincheck" &&
            strSubCommand != "floodingwallet:maxcheck" &&
            strSubCommand != "ddoswallet:detect" &&
            strSubCommand != "ddoswallet:denied" &&
            strSubCommand != "ddoswallet:ban" &&
            strSubCommand != "ddoswallet:bantime" &&
            strSubCommand != "ddoswallet:disconnect" &&
            strSubCommand != "ddoswallet:mincheck" &&
            strSubCommand != "eclipsewallet:detect" &&
            strSubCommand != "eclipsewallett:denied" &&
            strSubCommand != "eclipsewallet:ban" &&
            strSubCommand != "eclipsewallet:bantime" &&
            strSubCommand != "eclipsewallet:disconnect" &&
            strSubCommand != "eclipsewallet:mincheck" &&
            strSubCommand != "erebuswallet:detect" &&
            strSubCommand != "erebuswallett:denied" &&
            strSubCommand != "erebuswallet:ban" &&
            strSubCommand != "erebuswallet:bantime" &&
            strSubCommand != "erebuswallet:disconnect" &&
            strSubCommand != "erebuswallet:mincheck" &&
            strSubCommand != "bgpwallet:detect" &&
            strSubCommand != "bgpwallett:denied" &&
            strSubCommand != "bgpwallet:ban" &&
            strSubCommand != "bgpwallet:bantime" &&
            strSubCommand != "bgpwallet:disconnect" &&
            strSubCommand != "bgpwallet:mincheck" &&
            strSubCommand != "resettingsyncwallet:detect" &&
            strSubCommand != "resettingsyncwallett:denied" &&
            strSubCommand != "resettingsyncwallet:ban" &&
            strSubCommand != "resettingsyncwallet:bantime" &&
            strSubCommand != "resettingsyncwallet:disconnect" &&
            strSubCommand != "resettingsyncwallet:mincheck"

        ))

    {
        throw runtime_error(
                "firewall \"sub-command\"... ( \"argument1\" \"argument2\")\n"
                "Set of commands to execute firewall related actions\n"
                "\nParameters:\n"
                "1. \"sub-command\"     (string or set of strings, required) The command to execute\n"
                "2. \"argument 1\"        (string, optional) Argument parameter for the sub-command\n"
                "3. \"argument 2\"        (string, optional) Argument parameter for the sub-command\n"
                "\nAvailable commands/arguments:\n"
                "1.  getpeeraverageheight                   - Returns average blockheight among connected nodes.\n"
                "1.  getstatus                              - Get the status of Firewall.\n"
                "1.  setstatus                              - Set the status of Firewall.\n"
                "2.             true                        - Enables the firewall.\n"
                "2.             false                       - Enables the firewall.\n"
                "1.  getinfo                                - Get general firewall status.\n"
                "1.  cleardenied                            - Auto-clear denied list upon Firewall execution.\n"
                "2.             true                        - Enables auto-clear denied list.\n"
                "2.             false                       - Disables auto-clear denied list.\n"
                "1.  clearbanned                            - Auto-clear denied list upon Firewall execution.\n"
                "2.             true                        - Enables auto-clear denied list.\n"
                "2,             false                       - Disables auto-clear denied list.\n"
                "1.  debug:enabled                          - Set the status of live-debugging.\n"
                "2.             true                        - Enables live-debugging.\n"
                "2,             false                       - Disables live-debugging.\n"
                "1.  debug:exam                             - Set the status of live-debugging for Examination.\n"
                "2.             true                        - Enables live-debugging for Examination.\n"
                "2,             false                       - Disables live-debugging for Examination.\n"
                "1.  debug:bans                             - Set the status of live-debugging for Bans.\n"
                "2.             true                        - Enables live-debugging for Bans.\n"
                "2,             false                       - Disables live-debugging for Bans.\n"
                "1.  debug:denied                           - Set the status of live-debugging for Denied.\n"
                "2.             true                        - Enables live-debugging for Denied.\n"
                "2,             false                       - Disables live-debugging for Denied.\n"
                "1.  debug:disconnect                       - Set the status of live-debugging for Disconnect.\n"
                "2.             true                        - Enables live-debugging for Disconnect.\n"
                "2,             false                       - Disables live-debugging for Disconnect.\n"
                "1.  debug:doublespend                      - Set the status of live-debugging for Double Spend.\n"
                "2.             true                        - Enables live-debugging for Double Spend.\n"
                "2,             false                       - Disables live-debugging for Double Spend.\n"
                "1.  debug:invalidwallet                    - Set the status of live-debugging for Invalid Wallet.\n"
                "2.             true                        - Enables live-debugging for Invalid Wallet.\n"
                "2,             false                       - Disables live-debugging for Invalid Wallet.\n"
                "1.  debug:forkedwallet                     - Set the status of live-debugging for Forked Wallet.\n"
                "2.             true                        - Enables live-debugging for Forked Wallet.\n"
                "2,             false                       - Disables live-debugging for Forked Wallet.\n"
                "1.  debug:floodingwallet                   - Set the status of live-debugging for Flooding Wallets.\n"
                "2.             true                        - Enables live-debugging for Flooding Wallet.\n"
                "2,             false                       - Disables live-debugging for Flooding Wallet.\n"
                "1.  debug:ddoswallet                       - Set the status of live-debugging for DDoS Wallets.\n"
                "2.             true                        - Enables live-debugging for Flooding Wallet.\n"
                "2,             false                       - Disables live-debugging for Flooding Wallet.\n"
                "1.  debug:eclipsewallet                    - Set the status of live-debugging for Eclipse Wallets.\n"
                "2.             true                        - Enables live-debugging for Eclipse Wallet.\n"
                "2,             false                       - Disables live-debugging for Eclipse Wallet.\n"
                "1.  debug:erebuswallet                     - Set the status of live-debugging for Erebus Wallets.\n"
                "2.             true                        - Enables live-debugging for Erebus Wallet.\n"
                "2,             false                       - Disables live-debugging for Erebus Wallet.\n"
                "1.  debug:bgpwallet                        - Set the status of live-debugging for BGP Hijack Wallets.\n"
                "2.             true                        - Enables live-debugging for BGP Hijack Wallet.\n"
                "2,             false                       - Disables live-debugging for BGP Hijack Wallet.\n"
                "1.  debug:resetsyncwallet                  - Set the status of live-debugging for Reset Sync Wallets.\n"
                "2.             true                        - Enables live-debugging for Reset Sync Wallet.\n"
                "2,             false                       - Disables live-debugging for Reset Sync Wallet.\n"
                "1.  averagetolerance                       - Set the Exam Setting (Average Tolerance).\n"
                "2.             tolerance                   - Integer number (10)\n"
                "1.  averagerange                           - Set the Exam Setting (Average Block Range).\n"
                "2.             zone                        - Integer number (1)\n"
                "1.  traffictolerance                       - Set the Exam Setting (Traffic Tolerance).\n"
                "2.             tolerance                   - Double number (0.01)\n"
                "1.  trafficzone                            - Set the Exam Setting (Traffic Zone).\n"
                "2.             zone                        - Double number (0.01)\n"
                "1.  addtoallowed                           - Adds IP address to allowed list.\n"
                "2.             IP                          - String address (127.0.0.1)\n"
                "1.  addtodenied                            - Adds IP address to denied list.\n"
                "2.             IP                          - String address (127.0.0.1)\n"
                "1.  bandwidthabuse:detect                  - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bandwidthabuse:denied                  - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bandwidthabuse:ban                     - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bandwidthabuse:bantime                 - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  bandwidthabuse:disconnect              - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bandwidthabuse:mincheck                - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  doublespend:detect                     - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  doublespend:denied                     - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  doublespend:ban                        - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  doublespend:bantime                    - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  doublespend:disconnect                 - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  doublespend:mincheck                   - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  doublespend:minattack                  - Adjust attack detection minimum ratio.\n"
                "2.             Value                       - Double (byte ratio) (17.1)\n" 
                "1.  doublespend:maxattack                  - Adjust attack detection maximum ratio.\n"
                "2.             Value                       - Double (byte ratio) (17.2)\n" 
                "1.  invalidwallet:detect                   - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  invalidwallet:denied                   - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  invalidwallet:ban                      - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  invalidwallet:bantime                  - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  invalidwallet:disconnect               - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  invalidwallet:minprotocol              - Adjust default minimum protocol version.\n"
                "2.             Version                     - Integer number (1007)\n" 
                "1.  invalidwallet:mincheck                 - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  forkedwallet:detect                    - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  forkedwallet:denied                    - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  forkedwallet:ban                       - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  forkedwallet:bantime                   - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  forkedwallet:disconnect                - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  forkedwallet:mincheck                  - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  forkedwallet:nodeheight                - Adds a Forked Wallet NodeHeight\n"
                "2.             Time                        - Integer blocknumber (300)\n" 
                "1.  floodingwallet:detect                  - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  floodingwallet:denied                  - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  floodingwallet:ban                     - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  floodingwallet:bantime                 - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  floodingwallet:disconnect              - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  floodingwallet:mincheck                - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  floodingwallet:minbytes                - Adjust attack detection minimum bytes.\n"
                "2.             Time                        - Integer bytes (30000)\n" 
                "1.  floodingwallet:maxbytes                - Adjust attack detection maximum bytes.\n"
                "2.             Time                        - Integer bytes (30000)\n"
                "1.  floodingwallet:attackpattern:add       - Adjust attack detection pattern add.\n"
                "2.             Warnings                    - Integer bytes (30000)\n"
                "1.  floodingwallet:attackpattern:remove    - Adjust attack detection pattern remove.\n"
                "2.             Warnings                    - Integer bytes (30000)\n"
                "1.  floodingwallet:attackignored:add       - Adjust attack detection ignored add.\n"
                "2.             Warnings                    - Integer bytes (30000)\n"
                "1.  floodingwallet:attackignored:remove    - Adjust attack detection ignored remove.\n"
                "2.             Warnings                    - Integer bytes (30000)\n"
                "1.  floodingwallet:mintrafficavg           - Adjust minimum traffic average range.\n"
                "2.             Ratio                       - Double (10.01)\n"
                "1.  floodingwallet:maxtrafficavg           - Adjust maximum traffic average range.\n"
                "2.             Ratio                       - Double (20.01)\n"
                "1.  floodingwallet:mincheck                - Adjust attack detection minimum time.\n"
                "2.             Time                        - Integer (30)\n" 
                "1.  floodingwallet:maxcheck                - Adjust attack detection minimum time.\n"
                "2.             Time                        - Integer (60)\n" 
                "1.  ddoswallet:detect                      - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  ddoswallet:denied                      - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  ddoswallet:ban                         - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  ddoswallet:bantime                     - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  ddoswallet:disconnect                  - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  ddoswallet:mincheck                    - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  eclipsewallet:detect                   - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  eclipsewallett:denied                  - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  eclipsewallet:ban                      - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  eclipsewallet:bantime                  - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  eclipsewallet:disconnect               - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  eclipsewallet:mincheck                 - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  erebuswallet:detect                    - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  erebuswallett:denied                   - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  erebuswallet:ban                       - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  erebuswallet:bantime                   - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  erebuswallet:disconnect                - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  erebuswallet:mincheck                  - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  bgpwallet:detect                       - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bgpwallett:denied                      - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bgpwallet:ban                          - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bgpwallet:bantime                      - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  bgpwallet:disconnect                   - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  bgpwallet:mincheck                     - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  resettingsyncwallet:detect             - Turn detection on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  resettingsyncwallett:denied            - Turn denied list when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  resettingsyncwallet:ban                - Turn banning when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  resettingsyncwallet:bantime            - Adjust default ban time length.\n"
                "2.             Time                        - Integer seconds (30)\n" 
                "1.  resettingsyncwallet:disconnect         - Disconnect when detected on/off.\n"
                "2.             Status                      - Boolean true|false\n" 
                "1.  resettingsyncwallet:mincheck           - Adjust attack detection minimum check time.\n"
                "2.             Time                        - Integer seconds (30)\n" 

                );
    }


    /* ------------------------------------- */
    if (strSubCommand == "getpeeraverageheight")
    {
        if (fHelp)
        {
            throw runtime_error("getpeeraverageheight\n"
                                "Returns average blockheight among connected nodes.");
        }

        result.push_back(Pair("peeraverageheight",                  Firewall::Stats::AverageHeight));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "getstatus")
    {
        if (fHelp)
        {
            throw runtime_error("firewall getstatus\n"
                                "\nReturns the status of Firewall.\n"
                                );
	    }

        result.push_back(Pair("enabled",                            BoolToString(Firewall::Settings::Enabled)));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "setstatus")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall setstatus \"true|false\"\n"
                                "\nChange the status of Firewall.\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - true\n"
                                + HelpExampleCli("firewall setstatus", "true")
                                + HelpExampleCli("firewall setstatus", "false")
                                );
	    }

        Firewall::Settings::Enabled = StringToBool(strArgument1);

        result.push_back(Pair("enabled",                            BoolToString(Firewall::Settings::Enabled)));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "getinfo")
    {
        result.push_back(Pair("module-name",                        Firewall::Settings::ModuleName));
        result.push_back(Pair("enabled",                            BoolToString(Firewall::Settings::Enabled)));
        result.push_back(Pair("denied-clear",                       BoolToString(Firewall::Settings::Denied_Autoclear)));
        result.push_back(Pair("banned-clear",                       BoolToString(Firewall::Settings::Banned_Autoclear)));
        result.push_back(Pair("allcheck-maxtimer",                  Firewall::Settings::AllCheck_MaxTimer));
        result.push_back(Pair("banned_minnodes",                    Firewall::Settings::Banned_MinNodes));
        result.push_back(Pair("average-tolerance",                  Firewall::Settings::Average_Tolerance));
        result.push_back(Pair("average-range",                      Firewall::Settings::Average_Range));
        result.push_back(Pair("traffic-tolerance",                  Firewall::Settings::Traffic_Tolerance));
        result.push_back(Pair("traffic-zone",                       Firewall::Settings::Traffic_Zone));
        result.push_back(Pair("livedebug-detect",                   BoolToString(Firewall::LiveDebug::Enabled)));
        result.push_back(Pair("livedebug-exam",                     BoolToString(Firewall::LiveDebug::Exam)));
        result.push_back(Pair("livedebug-bans",                     BoolToString(Firewall::LiveDebug::Bans)));
        result.push_back(Pair("livedebug-denied",                   BoolToString(Firewall::LiveDebug::Denied)));
        result.push_back(Pair("livedebug-disconnect",               BoolToString(Firewall::LiveDebug::Disconnect)));
        result.push_back(Pair("livedebug-bandwidthabuse",           BoolToString(Firewall::LiveDebug::BandwidthAbuse)));
        result.push_back(Pair("livedebug-doublespend",              BoolToString(Firewall::LiveDebug::DoubleSpend)));
        result.push_back(Pair("livedebug-invalidwallet",            BoolToString(Firewall::LiveDebug::InvalidWallet)));
        result.push_back(Pair("livedebug-forkedwallet",             BoolToString(Firewall::LiveDebug::ForkedWallet)));
        result.push_back(Pair("livedebug-floodingwallet",           BoolToString(Firewall::LiveDebug::FloodingWallet)));
        result.push_back(Pair("bandwidthabuse-detect",              BoolToString(Firewall::BandwidthAbuse::Detect)));
        result.push_back(Pair("bandwidthabuse-denied",              BoolToString(Firewall::BandwidthAbuse::Denied)));
        result.push_back(Pair("bandwidthabuse-bantime",             (int64_t)Firewall::BandwidthAbuse::BanTime));
        result.push_back(Pair("bandwidthabuse-ban",                 BoolToString(Firewall::BandwidthAbuse::Ban)));
        result.push_back(Pair("invalidwallet-detect",               BoolToString(Firewall::InvalidWallet::Detect)));
        result.push_back(Pair("invalidwallet-denied",               BoolToString(Firewall::InvalidWallet::Denied)));
        result.push_back(Pair("invalidwallet-ban",                  BoolToString(Firewall::InvalidWallet::Ban)));
        result.push_back(Pair("invalidwallet-bantime",              (int64_t)Firewall::InvalidWallet::BanTime));
        result.push_back(Pair("floodingwallet-detect",              BoolToString(Firewall::FloodingWallet::Detect)));
        result.push_back(Pair("floodingwallet-denied",              BoolToString(Firewall::FloodingWallet::Denied)));
        result.push_back(Pair("floodingwallet-ban",                 BoolToString(Firewall::FloodingWallet::Ban)));
        result.push_back(Pair("floodingwallet-bantime",             (int64_t)Firewall::FloodingWallet::BanTime));
        result.push_back(Pair("forkedwallet-detect",                BoolToString(Firewall::ForkedWallet::Detect)));
        result.push_back(Pair("forkedwallet-denied",                BoolToString(Firewall::ForkedWallet::Denied)));
        result.push_back(Pair("forkedwallet-ban",                   BoolToString(Firewall::ForkedWallet::Ban)));
        result.push_back(Pair("forkedwallet-bantime",               (int64_t)Firewall::ForkedWallet::BanTime));
        result.push_back(Pair("ddoswallet-detect",                  BoolToString(Firewall::DDoSWallet::Detect)));
        result.push_back(Pair("ddoswallet-denied",                  BoolToString(Firewall::DDoSWallet::Denied)));
        result.push_back(Pair("ddoswallet-ban",                     BoolToString(Firewall::DDoSWallet::Ban)));
        result.push_back(Pair("ddoswallet-bantime",                 (int64_t)Firewall::DDoSWallet::BanTime));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "cleardenied")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall cleardenied \"true|false\"\n"
                                "\nFirewall Clear Denied list (session)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - false\n"
                                + HelpExampleCli("firewall cleardenied", "true")
                                + HelpExampleCli("firewall cleardenied", "false")
                                );
	    }

        Firewall::Settings::Denied_Autoclear = StringToBool(strArgument1);

        result.push_back(Pair("autoclear-denied",                   Firewall::Settings::Denied_Autoclear));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "clearbanned")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error(
                                "firewall clearbanned \"true|false\"\n"
                                "\nFirewall Clear Banned List (permenant)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - false\n"
                                + HelpExampleCli("firewall clearbanned", "true")
                                + HelpExampleCli("firewall clearbanned", "false")
                                );
	    }

        Firewall::Settings::Denied_Autoclear = StringToBool(strArgument1);

        result.push_back(Pair("autoclear-denied",                   Firewall::Settings::Denied_Autoclear));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:enabled")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:enabled \"true|false\"\n"
                                "\nFirewall Live Debug Output\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - false\n"
                                + HelpExampleCli("firewall debug", "true")
                                + HelpExampleCli("firewall debug", "false")
                                );
        }

        Firewall::LiveDebug::Enabled = StringToBool(strArgument1);

        result.push_back(Pair("live-debug",                         Firewall::LiveDebug::Enabled));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:bans")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:bans \"true|false\"\n"
                                "\nFirewall Live Debug Output - Bans\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - false\n"
                                + HelpExampleCli("firewall debug:bans", "true")
                                + HelpExampleCli("firewall debug:bans", "false")
                                );
        }

        Firewall::LiveDebug::Bans = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-bans",                    Firewall::LiveDebug::Bans));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:denied")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:denied \"true|false\"\n"
                                "\nFirewall Live Debug Output - Denied\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - true\n"
                                + HelpExampleCli("firewall debug:denied", "true")
                                + HelpExampleCli("firewall debug:denied", "false")
                                );
        }

        Firewall::LiveDebug::Denied = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-denied",                  Firewall::LiveDebug::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:disconnect")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:disconnect \"true|false\"\n"
                                "\nFirewall Live Debug Output - Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - true\n"
                                + HelpExampleCli("firewall debug:disconnect", "true")
                                + HelpExampleCli("firewall debug:disconnect", "false")
                                );
        }

        Firewall::LiveDebug::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-disconnect",              Firewall::LiveDebug::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:bandwidthabuse")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:bandwidthabuse \"true|false\"\n"
                                "\nFirewall Live Debug Output - Bandwidth Abuse\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - true\n"
                                + HelpExampleCli("firewall debug:bandwidthabuse", "true")
                                + HelpExampleCli("firewall debug:bandwidthabuse", "false")
                                );
	    }

        Firewall::LiveDebug::BandwidthAbuse = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-bandwidthabuse",          Firewall::LiveDebug::BandwidthAbuse));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:doublespend")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:doublespend \"true|false\"\n"
                                "\nFirewall Live Debug Output - No False Positive (Double Spend)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - true\n"
                                + HelpExampleCli("firewall debug:doublespend", "true")
                                + HelpExampleCli("firewall debug:doublepsend", "false")
                                );
	    }

        Firewall::LiveDebug::DoubleSpend = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-doublespend",             Firewall::LiveDebug::DoubleSpend));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:invalidwallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:invalidwallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - Invalid Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - true\n"
                                + HelpExampleCli("firewall debug:invalidwallet", "true")
                                + HelpExampleCli("firewall debug:invalidwallet", "false")
                                );
	    }

        Firewall::LiveDebug::InvalidWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-invalidwallet",           Firewall::LiveDebug::InvalidWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:forkedwallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:forkedwallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - Forked Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - true\n"
                                + HelpExampleCli("firewall debug:forkedwallet", "true")
                                + HelpExampleCli("firewall debug:forkedwallet", "false")
                                );
	    }

        Firewall::LiveDebug::ForkedWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-forkedwallet",            Firewall::LiveDebug::ForkedWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:floodingwallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:floodingwallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - Flooding Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall debug:floodingwallet", "true")
                                + HelpExampleCli("firewall debug:floodingwallet", "false")
                                );
	    }

        Firewall::LiveDebug::FloodingWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-floodingwallet",          Firewall::LiveDebug::FloodingWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:ddoswallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:ddoswallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - DDoS Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall debug:ddoswallet", "true")
                                + HelpExampleCli("firewall debug:ddoswallet", "false")
                                );
	    }

        Firewall::LiveDebug::DDoSWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-ddoswallet",              Firewall::LiveDebug::DDoSWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:eclipsewallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:eclipsewallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - Eclipse Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall debug:eclipsewallet", "true")
                                + HelpExampleCli("firewall debug:eclipsewallet", "false")
                                );
	    }

        Firewall::LiveDebug::EclipseWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-eclipsewallet",           Firewall::LiveDebug::EclipseWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:erebuswallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:erebuswallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - Erebus Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall debug:erebuswallet", "true")
                                + HelpExampleCli("firewall debug:erebuswallet", "false")
                                );
	    }

        Firewall::LiveDebug::ErebusWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-erebuswallet",            Firewall::LiveDebug::ErebusWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:bgpwallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:bgpwallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - BGP Hijack Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall debug:bgpwallet", "true")
                                + HelpExampleCli("firewall debug:bgpwallet", "false")
                                );
	    }

        Firewall::LiveDebug::BGPWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-bgpwallet",               Firewall::LiveDebug::BGPWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "debug:resetsyncwallet")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall debug:resetsyncwallet \"true|false\"\n"
                                "\nFirewall Live Debug Output - Resetting Sync Wallet\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall debug:resetsyncwallet", "true")
                                + HelpExampleCli("firewall debug:resetsyncwallet", "false")
                                );
	    }

        Firewall::LiveDebug::ResettingSyncWallet = StringToBool(strArgument1);

        result.push_back(Pair("live-debug-resetsyncwallet",         Firewall::LiveDebug::ResettingSyncWallet));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "averagetolerance")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall averagetolerance \"tolerance\"\n"
                                "\nFirewall Exam Setting (Average Block Tolerance)\n"
                                "\nArguments:\n"
                                "Value: \"tolerance\" (integer, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall averagetolerance", "1")
                                + HelpExampleCli("firewall averagetolerance", "5")
                                );
	    }

        Firewall::Settings::Average_Tolerance =  (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("settings-averagetolerance",          Firewall::Settings::Average_Tolerance));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "averagerange")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall averagerange \"zone\"\n"
                                "\nFirewall Exam Setting (Average Block Range)\n"
                                "\nArguments:\n"
                                "Value: \"tolerance\" (integer, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall averagerange", "1")
                                + HelpExampleCli("firewall averagerange", "5")
                                );
	    }

        Firewall::Settings::Average_Range =  (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("settings-averagerange",              Firewall::Settings::Average_Range));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "traffictolerance")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall traffictolerance \"tolerance\"\n"
                                "\nFirewall Exam Setting (Traffic Tolerance)\n"
                                "\nArguments:\n"
                                "Value: \"tolerance\" (double, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall traffictolerance", "0.0001")
                                + HelpExampleCli("firewall traffictolerance", "0.1")
                                );
	    }

        Firewall::Settings::Traffic_Tolerance = StringToBool(strArgument1);

        result.push_back(Pair("settings-traffictolerance",          Firewall::Settings::Traffic_Tolerance));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "trafficzone")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall trafficzone \"zone\"\n"
                                "\nFirewall Exam Setting (Traffic Zone)\n"
                                "\nArguments:\n"
                                "Value: \"zone\" (double), required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall trafficzone", "10.10")
                                + HelpExampleCli("firewall trafficzone", "50.50")
                                );
	    }

        Firewall::Settings::Traffic_Zone = strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("settings-trafficzone",               Firewall::Settings::Traffic_Zone));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "addtoallowed")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall addtoallowed \"address\"\n"
                                "\nFirewall Adds IP Address to General\n"
                                "\nArguments:\n"
                                "Value: \"address\" (string, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall addtoallowed", "IP")
                                + HelpExampleCli("firewall addtoallowed", "127.0.0.1")
                                );
	    }

        if (CountStringArray(Firewall::Lists::Allowed) < 256)
        {
            Firewall::Lists::Allowed[CountStringArray(Firewall::Lists::Allowed)] = strArgument1;

            MSG = CountStringArray(Firewall::Lists::Allowed);
        }
        else
        {
            MSG = "Over 256 Max!";
        }

        result.push_back(Pair("lists-allowed-add",                  MSG));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "addtodenied")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error(
                                "firewall addtodenied \"address\"\n"
                                "\nFirewall Adds IP Address to General\n"
                                "\nArguments:\n"
                                "Value: \"address\" (string, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall addtodenied", "IP")
                                + HelpExampleCli("firewall addtodenied", "127.0.0.1")
                                );
	    }

        if (CountStringArray(Firewall::Lists::Denied) < 256)
        {
            Firewall::Lists::Denied[CountStringArray(Firewall::Lists::Denied)] = strArgument1;

            MSG = CountStringArray(Firewall::Lists::Denied);
        }
        else
        {
            MSG = "Over 256 Max!";
        }

        result.push_back(Pair("lists-denied-add",                   MSG));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bandwidthabuse:detect")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bandwidthabuse:detect \"true|false\"\n"
                                "\nFirewall Bandwidth Abuse Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bandwidthabuse:detect", "true")
                                + HelpExampleCli("firewall bandwidthabuse:detect", "false")
                                );
	    }

        Firewall::BandwidthAbuse::Detect = StringToBool(strArgument1);

        result.push_back(Pair("bandwidthabuse-detect",              Firewall::BandwidthAbuse::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bandwidthabuse:denied")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bandwidthabuse:denied \"true|false\"\n"
                                "\nFirewall Bandwidth Abuse Denied List (session)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bandwidthabuse:denied", "true")
                                + HelpExampleCli("firewall bandwidthabuse:denied", "false")
                                );
	    }

        Firewall::BandwidthAbuse::Denied = StringToBool(strArgument1);

        result.push_back(Pair("banwidthabuse-denied",               Firewall::BandwidthAbuse::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bandwidthabuse:ban")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bandwidthabuse:ban \"true|false\"\n"
                                "\nFirewall Bandwidth Abuse Ban (permenant)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bandwidthabuse:ban", "true")
                                + HelpExampleCli("firewall bandwidthabuse:ban", "false")
                                );
	    }

        Firewall::BandwidthAbuse::Ban = StringToBool(strArgument1);

        result.push_back(Pair("bandwidthabuse-ban",                 Firewall::BandwidthAbuse::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bandwidthabuse:bantime")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bandwidthabuse:bantime \"seconds\"\n"
                                "\nFirewall Bandwidth Abuse Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"0|10000\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - 24h\n"
                                + HelpExampleCli("firewall bandwidthabuse:bantime", "0")
                                + HelpExampleCli("firewall bandwidthabuse:bantime", "10000000")
                                );
	    }

        Firewall::BandwidthAbuse::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("bandwidthabuse-bantime",             Firewall::BandwidthAbuse::BanTime));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bandwidthabuse:disconnect")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bandwidthabuse:disconnect \"true|false\"\n"
                                "\nFirewall Bandwidth Abuse Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bandwidthabuse:disconnect", "true")
                                + HelpExampleCli("firewall bandwidthabuse:disconnect", "false")
                                );
	    }

        Firewall::BandwidthAbuse::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("bandwidthabuse-disconnect",          Firewall::BandwidthAbuse::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bandwidthabuse:mincheck")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bandwidthabuse:mincheck \"seconds\"\n"
                                "\nFirewall Bandwidth Abuse Min Check\n"
                                "\nArguments:\n"
                                "Seconds: \"0|10000\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default\n"
                                + HelpExampleCli("firewall bandwidthabuse:mincheck", "0")
                                + HelpExampleCli("firewall bandwidthabuse:mincheck", "10000000")
                                );
	    }

        Firewall::BandwidthAbuse::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("bandwidthabuse-mincheck",            Firewall::BandwidthAbuse::MinCheck));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:detect")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:detect \"true|false\"\n"
                                "\nFirewall Double Spend Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall doublespend:detect", "true")
                                + HelpExampleCli("firewall doublespend:detect", "false")
                                );
	    }

        Firewall::DoubleSpend::Detect = StringToBool(strArgument1);

        result.push_back(Pair("doublespend-detect",                 Firewall::DoubleSpend::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:denied")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:denied \"true|false\"\n"
                                "\nFirewall Double Spend Denied (session)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall doublespend:denied", "true")
                                + HelpExampleCli("firewall doublespend:denied", "false")
                                );
	    }

        Firewall::DoubleSpend::Denied = StringToBool(strArgument1);

        result.push_back(Pair("doublespend-denied",                 Firewall::DoubleSpend::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:ban")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:ban \"true|false\"\n"
                                "\nFirewall Double Spend Ban (permenant)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall doublespend:ban", "true")
                                + HelpExampleCli("firewall doublespend:ban", "false")
                                );
	    }

        Firewall::DoubleSpend::Ban = StringToBool(strArgument1);

        result.push_back(Pair("doublespend-ban",                    Firewall::DoubleSpend::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:bantime")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:bantime \"true|false\"\n"
                                "\nFirewall Double Spend Ban Time (permenant)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall doublespend:bantime", "true")
                                + HelpExampleCli("firewall doublespend:bantime", "false")
                                );
	    }

        Firewall::DoubleSpend::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("doublespend-bantime",                Firewall::DoubleSpend::BanTime));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:disconnect")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:disconnect \"true|false\"\n"
                                "\nFirewall Double Spend Disconnect (permenant)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall doublespend:disconnect", "true")
                                + HelpExampleCli("firewall doublespend:disconnect", "false")
                                );
	    }

        Firewall::DoubleSpend::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("doublespend-disconnect",             Firewall::DoubleSpend::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:mincheck \"seconds\"\n"
                                "\nFirewall Bandwidth Abuse Min Check\n"
                                "\nArguments:\n"
                                "Seconds: \"0|10000\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default\n"
                                + HelpExampleCli("firewall doublespend:mincheck", "0")
                                + HelpExampleCli("firewall doublespend:mincheck", "10000000")
                                );
        }

        Firewall::DoubleSpend::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("doublespend-mincheck",               Firewall::DoubleSpend::MinCheck));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:minattack")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:minattack \"value\"\n"
                                "\nFirewall Double Spend Min Attack\n"
                                "\nArguments:\n"
                                "Value: \"17.1\" (double, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - 17.1\n"
                                + HelpExampleCli("firewall doublespend:minattack", "17.1")
                                + HelpExampleCli("firewall doublespend:minattack", "17.005")
                                );
        }

        Firewall::DoubleSpend::MinAttack = strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("doublespend-minattack", Firewall::DoubleSpend::MinAttack));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "doublespend:maxattack")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall doublespend:maxattack \"ratio\"\n"
                                "\nFirewall Double Spend Max Attack\n"
                                "\nArguments:\n"
                                "Value: \"17.2\" (double, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - 17.2\n"
                                + HelpExampleCli("firewall doublespend:maxattack", "17.2")
                                + HelpExampleCli("firewall doublespend:maxattack", "18.004")
                                );
        }

        Firewall::DoubleSpend::MaxAttack = strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("doublespend-maxattack", Firewall::DoubleSpend::MaxAttack));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "invalidwallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall invalidwallet:detect \"true|false\"\n"
                                "\nFirewall Invalid Wallet Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall invalidwallet:detect", "true")
                                + HelpExampleCli("firewall invalidwallet:detect", "false")
                                );
        }

        Firewall::InvalidWallet::Detect = StringToBool(strArgument1);

        result.push_back(Pair("invalidwallet-detect", Firewall::InvalidWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "invalidwallet:denied")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall invalidwallet:denied \"true|false\"\n"
                                "\nFirewall Invalid Wallet Denied List\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall invalidwallet:denied", "true")
                                + HelpExampleCli("firewall invalidwallet:denied", "false")
                                );
        }

        Firewall::InvalidWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("invalidwallet-denied", Firewall::InvalidWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "invalidwallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall invalidwallet:ban \"true|false\"\n"
                                "\nFirewall Invalid Wallet Ban List\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall invalidwallet:ban", "true")
                                + HelpExampleCli("firewall invalidwallet:ban", "false")
                                );
        }

        Firewall::InvalidWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("invalidwallet-ban", Firewall::InvalidWallet::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "invalidwallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall invalidwallet:bantime \"seconds\"\n"
                                "\nFirewall Invalid Wallet Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"0|100000\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - 24h\n"
                                + HelpExampleCli("firewall invalidwallet:bantime", "0")
                                + HelpExampleCli("firewall invalidwallet:bantime", "10000000")
                                );
        }

        Firewall::InvalidWallet::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("invalidwallet-bantime", Firewall::InvalidWallet::BanTime));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "invalidwallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall invalidwallet:disconnect \"true|false\"\n"
                                "\nFirewall Invalid Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall invalidwallet:disconnect", "true")
                                + HelpExampleCli("firewall invalidwallet:disconnect", "false")
                                );
        }

        Firewall::InvalidWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("invalidwallet-disconnect", Firewall::InvalidWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "invalidwallet:minprotocol")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall invalidwallet:minprotocol \"protocol\"\n"
                                "\nFirewall Invalid Wallet Min Protocol\n"
                                "\nArguments:\n"
                                "Value: \"0|100000\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall invalidwallet:minprotocol", "0")
                                + HelpExampleCli("firewall invalidwallet:minprotocol", "10000000")
                                );
        }

        Firewall::InvalidWallet::MinimumProtocol = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("invalidwallet-minprotocol", Firewall::InvalidWallet::MinimumProtocol));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "invalidwallet:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall invalidwallet:mincheck \"seconds\"\n"
                                "\nFirewall Invalid Wallet Max Check\n"
                                "\nArguments:\n"
                                "Value: \"0|100000\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall invalidwallet:mincheck", "0")
                                + HelpExampleCli("firewall invalidwallet:mincheck", "10000000")
                                );
        }

        Firewall::InvalidWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("invalidwallet-mincheck", Firewall::InvalidWallet::MinCheck));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "forkedwallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall forkedwallet:detect \"true|false\"\n"
                                "\nFirewall Forked Wallet Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall forkedwallet:detect", "true")
                                + HelpExampleCli("firewall forkedwallet:detect", "false")
                                );
        }

        Firewall::ForkedWallet::Detect = StringToBool(strArgument1);

        result.push_back(Pair("forkedwallet-detect", Firewall::ForkedWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "forkedwallet:denied")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall forkedwallet:denied \"true|false\"\n"
                                "\nFirewall Forked Wallet Denied List (session)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall forkedwallet:denied", "true")
                                + HelpExampleCli("firewall forkedwallet:denied", "false")
                                );
        }

        Firewall::ForkedWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("forkedwallet-denied", Firewall::ForkedWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "forkedwallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall forkedwallet:ban \"true|false\"\n"
                                "\nFirewall Forked Wallet Ban List (permenant))\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall forkedwallet:ban", "true")
                                + HelpExampleCli("firewall forkedwallet:ban", "false")
                                );
        }

        Firewall::ForkedWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("forkedwallet-ban", Firewall::ForkedWallet::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "forkedwallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall forkedwallet:bantime \"seconds\"\n"
                                "\nFirewall Forked Wallet Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - 24h\n"
                                + HelpExampleCli("firewall forkedwallet:bantime", "0")
                                + HelpExampleCli("firewall forkedwallet:bantime", "10000000")
                                );
        }

        Firewall::ForkedWallet::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("bantime-forkedwallet", Firewall::ForkedWallet::BanTime));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "forkedwallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall forkedwallet:disconnect \"true|false\"\n"
                                "\nFirewall Forked Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall forkedwallet:disconnect", "true")
                                + HelpExampleCli("firewall forkedwallet:disconnect", "false")
                                );
        }

        Firewall::ForkedWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("disconnect-forkedwallet", Firewall::ForkedWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "forkedwallet:mincheck")
    {
	    if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall forkedwallet:mincheck \"seconds\"\n"
                                "\nFirewall Forked Wallet Min Check\n"
                                "\nArguments:\n"
                                "Seconds: \"0|10000\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default\n"
                                + HelpExampleCli("firewall forkedwallet:mincheck", "0")
                                + HelpExampleCli("firewall forkedwallet:mincheck", "10000000")
                                );
	    }

        Firewall::ForkedWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("forkedwallet-mincheck",            Firewall::ForkedWallet::MinCheck));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "forkedwallet:nodeheight")
    {
        // TODO: Upgrade to std::list<std::string> std::list<int>   FIREWALL_FORKED_NODEHEIGHT.push_back() 

        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall forkedwallet:nodeheight \"blockheight\"\n"
                                "\nFirewall Adds a Forked Wallet NodeHeight \n"
                                "\nArguments:\n"
                                "Value: \"blockheight\" (int, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall forkedwallet:nodeheight", "0")
                                + HelpExampleCli("firewall forkedwallet:nodeheight", "10000000")
                                );
        }

        if (CountIntArray(Firewall::ForkedWallet::NodeHeight) < 256)
        {
            Firewall::ForkedWallet::NodeHeight[CountIntArray(Firewall::ForkedWallet::NodeHeight)] = (int)strtod(params[1].get_str().c_str(), NULL);
            
            MSG = CountIntArray(Firewall::ForkedWallet::NodeHeight);
        }
        else
        {
            MSG = "Over 256 Max!";
        }

        result.push_back(Pair("forkedwallet-nodeheight-count", MSG));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:detect \"true|false\"\n"
                                "\nFirewall Flooding Wallet Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall floodingwallet:detect", "true")
                                + HelpExampleCli("firewall floodingwallet:detect", "false")
                                );
        }

        Firewall::FloodingWallet::Detect = StringToBool(strArgument1);

        result.push_back(Pair("floodingwallet-detect", Firewall::FloodingWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:denied")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:denied \"true|false\"\n"
                                "\nFirewall Flooding Wallet Denied (session)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall floodingwallet:denied", "true")
                                + HelpExampleCli("firewall floodingwallet:denied", "false")
                                );
        }

        Firewall::FloodingWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("floodingwallet-denied", Firewall::FloodingWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:ban \"true|false\"\n"
                                "\nFirewall Flooding Wallet Ban (permenant)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall floodingwallet:ban", "true")
                                + HelpExampleCli("firewall floodingwallet:ban", "false")
                                );
        }

        Firewall::FloodingWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("ban-floodingwallet", Firewall::FloodingWallet::Ban));
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:bantime \"seconds\"\n"
                                "\nFirewall Flooding Wallet Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - 24h\n"
                                + HelpExampleCli("firewall floodingwallet:bantime", "0")
                                + HelpExampleCli("firewall floodingwallet:bantime", "10000000")
                                );
        }

        Firewall::FloodingWallet::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("floodingwallet-bantime", Firewall::FloodingWallet::BanTime));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:disconnect \"true|false\"\n"
                                "\nFirewall Flooding Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall floodingwallet:disconnect", "true")
                                + HelpExampleCli("firewall floodingwallet:disconnect", "false")
                                );
        }

        Firewall::FloodingWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("floodingwallet-disconnect", Firewall::FloodingWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:minbytes")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:minbytes \"bytes\"\n"
                                "\nFirewall Flooding Wallet Min Bytes \n"
                                "\nArguments:\n"
                                "Value: \"Bytes\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - h\n"
                                + HelpExampleCli("firewall floodingwallet:minbytes", "0")
                                + HelpExampleCli("firewall floodingwallet:minbytes", "10000000")
                                );
        }

        Firewall::FloodingWallet::MinBytes = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("floodingwallet-minbytes", Firewall::FloodingWallet::MinBytes));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:maxbytes")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:maxbytes \"bytes\"\n"
                                "\nFirewall Flooding Wallet Max Bytes\n"
                                "\nArguments:\n"
                                "Value: \"bytes\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwalletmaxbytes", "0")
                                + HelpExampleCli("firewall floodingwalletmaxbytes", "10000000")
                                );
        }

        Firewall::FloodingWallet::MaxBytes = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("floodingwallet-bantime", Firewall::FloodingWallet::MaxBytes));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:attackpattern:add")
    {
        // TODO: Upgrade to vector<string>

        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:attackpattern:add \"warnings\"\n"
                                "\nFirewall Flooding Wallet Add Attack Pattern\n"
                                "\nArguments:\n"
                                "Value: \"warnings\" (string, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwallet:attackpattern:add", "0")
                                + HelpExampleCli("firewall floodingwallet:attackpattern:add", "10000000")
                                );
        }

        if (CountStringArray(Firewall::FloodingWallet::Patterns) < 256)
        {
            Firewall::FloodingWallet::Patterns[CountStringArray(Firewall::FloodingWallet::Patterns)] = strArgument1;
            
            MSG = "OK!";
        }
        else
        {
            MSG = "Over 256 Max!";
        }

        result.push_back(Pair("floodingwallet-attackpattern-add",
            strprintf("%s %d (%s)", strArgument1, CountStringArray(Firewall::FloodingWallet::Patterns), MSG)));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:attackpattern:remove")
    {
        // TODO: Upgrade to vector<string> Firewall::FloodingWallet_Patterns 

        int i;

        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:attackpattern:remove \"warnings\"\n"
                                "\nFirewall Flooding Wallet Remove Attack Pattern\n"
                                "\nArguments:\n"
                                "Value: \"warnings\" (string, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwallet:attackpattern:remove", "0")
                                + HelpExampleCli("firewall floodingwallet:attackpattern:remove", "10000000")
                                );
        }

        int TmpFloodPatternsCount;
        
        TmpFloodPatternsCount = CountStringArray(Firewall::FloodingWallet::Patterns);

        MSG = "Not Found";

        for (i = 0; i < TmpFloodPatternsCount; i++)
        {  
            if (strArgument1 == Firewall::FloodingWallet::Patterns[i])
            {
                MSG = i;

                Firewall::FloodingWallet::Patterns[i] = "";
            }
        }

        result.push_back(Pair("floodingwallet-attackpattern-remove",
            strprintf("%s %d (%s)", strArgument1, CountStringArray(Firewall::FloodingWallet::Patterns), MSG)));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:attackignored:add")
    {
        // TODO: Upgrade to vector<string> 

        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:attackignored:add \"warnings\"\n"
                                "\nFirewall Flooding Wallet Add Attack Ignored\n"
                                "\nArguments:\n"
                                "Value: \"warnings\" (string, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwallet:attackignored:add", "0")
                                + HelpExampleCli("firewall floodingwallet:attackignored:add", "10000000")
                                );
        }

        if (CountStringArray(Firewall::FloodingWallet::Ignored) < 256)
        {
            Firewall::FloodingWallet::Ignored[CountStringArray(Firewall::FloodingWallet::Ignored)] = strArgument1;

            MSG = MSG = "Ok!";;
        }
        else
        {
            MSG = "Over 256 Max!";
        }

        result.push_back(Pair("floodingwallet-attackignored-add",
            strprintf("%s %d (%s)", strArgument1, CountStringArray(Firewall::FloodingWallet::Ignored), MSG)));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:attackignored:remove")
    {
        // TODO: Upgrade to vector<string> Firewall::FloodingWallet_remove

        int i;

        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:attackignored:remove \"warnings\"\n"
                                "\nFirewall Flooding Wallet Remove Attack Ignored\n"
                                "\nArguments:\n"
                                "Value: \"warnings\" (string, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwallet:attackignored:remove", "0")
                                + HelpExampleCli("firewall floodingwallet:attackignored:remove", "10000000")
                                );
        }

        int TmpFloodIgnoredCount;
        
        TmpFloodIgnoredCount = CountStringArray(Firewall::FloodingWallet::Ignored);

        MSG = "Not Found";

        for (i = 0; i < TmpFloodIgnoredCount; i++)
        {  
            if (strArgument1 == Firewall::FloodingWallet::Ignored[i])
            {
                MSG = i;

                Firewall::FloodingWallet::Ignored[i] = "";
            }
        }

        result.push_back(Pair("floodingwallet-attackignored-remove",
            strprintf("%s %d (%s)", strArgument1, CountStringArray(Firewall::FloodingWallet::Ignored), MSG)));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:mintrafficavg")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:mintrafficavg \"ratio\"\n"
                                "\nFirewall Flooding Wallet Min Traffic Average\n"
                                "\nArguments:\n"
                                "Value: \"ratio\" (double, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - 2000\n"
                                + HelpExampleCli("firewall floodingwallet:mintrafficav", "20000.01")
                                + HelpExampleCli("firewall floodingwallet:mintrafficav", "12000.014")
                                );
        }

        Firewall::FloodingWallet::MinTrafficAverage = strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("floodingwallet-mintrafficavg", Firewall::FloodingWallet::MinTrafficAverage));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet::maxtrafficavg")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet::maxtrafficavg \"ratio\"\n"
                                "\nFirewall Flooding Wallet Max Traffic Average\n"
                                "\nArguments:\n"
                                "Value: \"ratio\" (double, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwallet:maxtrafficavg", "100.10")
                                + HelpExampleCli("ffirewall floodingwallet:maxtrafficavg", "10.8")
                                );
        }

        Firewall::FloodingWallet::MaxTrafficAverage = strtod(params[1].get_str().c_str(), NULL);;

        result.push_back(Pair("floodingwallet-maxtrafficavg", Firewall::FloodingWallet::MaxTrafficAverage));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:mincheck \"seconds\"\n"
                                "\nFirewall Ban Time Flooding Wallet Rule\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwallet:mincheck", "0")
                                + HelpExampleCli("firewall floodingwallet:mincheck", "10000000")
                                );
        }

        Firewall::FloodingWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("floodingwallet-mincheck", Firewall::FloodingWallet::MinCheck));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "floodingwallet:maxcheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall floodingwallet:maxcheck \"seconds\"\n"
                                "\nFirewall Flooding Wallet Max Check Time\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall floodingwallet:maxcheck", "0")
                                + HelpExampleCli("firewall floodingwallet:maxcheck", "10000000")
                                );
        }

        Firewall::FloodingWallet::MaxCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("floodingwallet-maxcheck", Firewall::FloodingWallet::MaxCheck));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "ddoswallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall ddoswallet:detect \"true|false\"\n"
                                "\nFirewall Detect DDoS Wallet Rule\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall ddoswallet:detect", "true")
                                + HelpExampleCli("firewall ddoswallet:detect", "false")
                                );
        }

        Firewall::DDoSWallet::Detect = StringToBool(strArgument1);

        result.push_back(Pair("ddoswallet-detect", Firewall::DDoSWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall ddoswallet:denied \"true|false\"\n"
                                "\nFirewall DDoS Wallet Denied List (session)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall ddoswallet:denied", "true")
                                + HelpExampleCli("firewall ddoswallet:denied", "false")
                                );
        }

        Firewall::DDoSWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("ddoswallet-denied", Firewall::DDoSWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "ddoswallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall ddoswallet:ban \"true|false\"\n"
                                "\nFirewall DDoS Wallet Ban (permenant)\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall ddoswallet:ban", "true")
                                + HelpExampleCli("firewall ddoswallet:ban", "false")
                                );
        }

        Firewall::DDoSWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("ddoswallet-ban", Firewall::DDoSWallet::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "ddoswallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall ddoswallet:bantime \"seconds\"\n"
                                "\nFirewall DDoS Wallet Ban (permenant)\n"
                                "\nArguments:\n"
                                "Time: \"true|false\" (integer, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall ddoswallet:bantime", "1000")
                                + HelpExampleCli("firewall ddoswallet:bantime", "2000")
                                );
        }

        Firewall::DDoSWallet::BanTime = StringToBool(strArgument1);

        result.push_back(Pair("ddoswallet-bantime", Firewall::DDoSWallet::BanTime));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "ddoswallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall ddoswallet:disconnect \"true|false\"\n"
                                "\nFirewall DDoS Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall ddoswallet:disconnect", "true")
                                + HelpExampleCli("firewall ddoswallet:disconnect", "false")
                                );
        }

        Firewall::DDoSWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("ddoswallet-disconnect", Firewall::DDoSWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "ddoswallet:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall ddoswallet:mincheck \"seconds\"\n"
                                "\nFirewall DDoS Wallet Min Check\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall ddoswallet:mincheck", "0")
                                + HelpExampleCli("firewall ddoswallet:mincheck", "10000000")
                                );
        }

        Firewall::DDoSWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("ddoswallet-mincheck", Firewall::DDoSWallet::MinCheck));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "eclipsewallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall eclipsewallet:detect \"true|false\"\n"
                                "\nFirewall Eclipse Wallet Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall eclipsewallet:detect", "0")
                                + HelpExampleCli("firewall eclipsewallet:detect", "10000000")
                                );
        }

        Firewall::EclipseWallet::Detect = StringToBool(params[1].get_str().c_str());

        result.push_back(Pair("eclipsewallet-detect", Firewall::EclipseWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "eclipsewallet:denied")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall eclipsewallet:denied \"true|false\"\n"
                                "\nFirewall Eclipse Wallet Denied\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall eclipsewallet:denied", "0")
                                + HelpExampleCli("firewall eclipsewallet:denied", "10000000")
                                );
        }

        Firewall::EclipseWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("eclipsewallet-detect", Firewall::EclipseWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "eclipsewallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall eclipsewallet:ban \"true|false\"\n"
                                "\nFirewall Eclipse Wallet Ban List\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall eclipsewallet:ban", "0")
                                + HelpExampleCli("firewall eclipsewallet:ban", "10000000")
                                );
        }

        Firewall::EclipseWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("eclipsewallet-ban", Firewall::EclipseWallet::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "eclipsewallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall eclipsewallet:bantime \"seconds\"\n"
                                "\nFirewall Eclipse Wallet Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall eclipsewallet:bantime", "0")
                                + HelpExampleCli("firewall eclipsewallet:bantime", "10000000")
                                );
        }

        Firewall::EclipseWallet::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("eclipsewallet-bantime", Firewall::EclipseWallet::BanTime));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "eclipsewallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall eclipsewallet:disconnect \"true|false\"\n"
                                "\nFirewall Eclipse Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall eclipsewallet:disconnect", "0")
                                + HelpExampleCli("firewall eclipsewallet:disconnect", "10000000")
                                );
        }

        Firewall::EclipseWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("eclipsewallet-disconnect", Firewall::EclipseWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "eclipsewallett:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall eclipsewallet:mincheck \"seconds\"\n"
                                "\nFirewall Eclipse Wallet Min Check\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall eclipsewallet:mincheck", "0")
                                + HelpExampleCli("firewall eclipsewallet:mincheck", "10000000")
                                );
        }

        Firewall::EclipseWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("eclipsewallet-mincheck", Firewall::EclipseWallet::MinCheck));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "erebuswallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall erebuswallet:detect \"true|false\"\n"
                                "\nFirewall Erebus Wallet Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall erebuswallet:detect", "0")
                                + HelpExampleCli("firewall erebuswallet:detect", "10000000")
                                );
        }

        Firewall::ErebusWallet::Detect = StringToBool(strArgument1);

        result.push_back(Pair("erebuswallet-detect", Firewall::ErebusWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "erebuswallet:denied")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall erebuswallet:denied \"true|false\"\n"
                                "\nFirewall Erebus Wallet Denied\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall erebuswallet:denied", "0")
                                + HelpExampleCli("firewall erebuswallet:denied", "10000000")
                                );
        }

        Firewall::ErebusWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("erebuswallet-detect", Firewall::ErebusWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "erebuswallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall erebuswallet:ban \"true|false\"\n"
                                "\nFirewall Erebus Wallet Ban List\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall erebuswallet:ban", "0")
                                + HelpExampleCli("firewall erebuswalletban", "10000000")
                                );
        }

        Firewall::ErebusWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("erebuswallet-ban", Firewall::ErebusWallet::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "erebuswallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall erebuswallet:bantime \"seconds\"\n"
                                "\nFirewall Erebus Wallet Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall erebuswallet:bantime", "0")
                                + HelpExampleCli("firewall erebuswallet:bantime", "10000000")
                                );
        }

        Firewall::ErebusWallet::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("erebuswallet-bantime", Firewall::ErebusWallet::BanTime));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "erebuswallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall erebuswallet:disconnect \"true|false\"\n"
                                "\nFirewall Erebus Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall erebuswallet:disconnect", "0")
                                + HelpExampleCli("firewall erebuswallet:disconnect", "10000000")
                                );
        }

        Firewall::ErebusWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("erebuswallet-disconnect", Firewall::ErebusWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "erebuswallet:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall erebuswallet:mincheck \"seconds\"\n"
                                "\nFirewall Erebus Wallet Min Check\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall erebuswallet:mincheck", "0")
                                + HelpExampleCli("firewall erebuswallet:mincheck", "10000000")
                                );
        }

        Firewall::ErebusWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("erebuswallet-mincheck", Firewall::ErebusWallet::MinCheck));

        return result;

    }
    /* ------------------------------------- */


    /* ------------------------------------- */
    if (strSubCommand == "bgpwallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bgpwallet:detect \"true|false\"\n"
                                "\nFirewall BGP Wallet Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bgpwallet:detect", "0")
                                + HelpExampleCli("firewall bgpwallet:detect", "10000000")
                                );
        }

        Firewall::BGPWallet::Detect = StringToBool(strArgument1);

        result.push_back(Pair("bgpwallet-detect", Firewall::BGPWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bgpwallet:denied")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bgpwallet:denied \"true|false\"\n"
                                "\nFirewall BGP Wallet Denied\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bgpwallet:denied", "0")
                                + HelpExampleCli("firewall bgpwallet:denied", "10000000")
                                );
        }

        Firewall::BGPWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("bgpwallet-detect", Firewall::BGPWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bgpwallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bgpwallet:ban \"true|false\"\n"
                                "\nFirewall BGP Wallet Ban List\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bgpwallet:ban", "0")
                                + HelpExampleCli("firewall bgpwalletban", "10000000")
                                );
        }

        Firewall::BGPWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("bgpwallet-ban", Firewall::BGPWallet::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bgpwallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bgpwallet:bantime \"seconds\"\n"
                                "\nFirewall BGP Wallet Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall bgpwallet:bantime", "0")
                                + HelpExampleCli("firewall bgpwallet:bantime", "10000000")
                                );
        }

        Firewall::BGPWallet::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("bgpwallet-bantime", Firewall::BGPWallet::BanTime));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bgpwallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bgpwallet:disconnect \"true|false\"\n"
                                "\nFirewall BGP Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall bgpwallet:disconnect", "0")
                                + HelpExampleCli("firewall bgpwallet:disconnect", "10000000")
                                );
        }

        Firewall::BGPWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("bgpwallet-disconnect", Firewall::BGPWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "bgpwallet:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall bgpwallet:mincheck \"seconds\"\n"
                                "\nFirewall BGP Wallet Min Check\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall bgpwallet:mincheck", "0")
                                + HelpExampleCli("firewall bgpwallet:mincheck", "10000000")
                                );
        }

        Firewall::BGPWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("bgpwallet-mincheck", Firewall::BGPWallet::MinCheck));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "resettingsyncwallet:detect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall resettingsyncwallet:detect \"true|false\"\n"
                                "\nFirewall ResettingSync Wallet Detect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall resettingsyncwallet:detect", "0")
                                + HelpExampleCli("firewall resettingsyncwallet:detect", "10000000")
                                );
        }

        Firewall::ResettingSyncWallet::Detect = StringToBool(strArgument1);

        result.push_back(Pair("resettingsyncwallet-detect", Firewall::ResettingSyncWallet::Detect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "resettingsyncwallet:denied")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall resettingsyncwallet:denied \"true|false\"\n"
                                "\nFirewall ResettingSync Wallet Denied\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall resettingsyncwallet:denied", "0")
                                + HelpExampleCli("firewall resettingsyncwallet:denied", "10000000")
                                );
        }

        Firewall::ResettingSyncWallet::Denied = StringToBool(strArgument1);

        result.push_back(Pair("resettingsyncwallet-detect", Firewall::ResettingSyncWallet::Denied));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "resettingsyncwallet:ban")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall resettingsyncwallet:ban \"true|false\"\n"
                                "\nFirewall ResettingSync Wallet Ban List\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall resettingsyncwallet:ban", "0")
                                + HelpExampleCli("firewall resettingsyncwalletban", "10000000")
                                );
        }

        Firewall::ResettingSyncWallet::Ban = StringToBool(strArgument1);

        result.push_back(Pair("resettingsyncwallet-ban", Firewall::ResettingSyncWallet::Ban));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "resettingsyncwallet:bantime")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall resettingsyncpwallet:bantime \"seconds\"\n"
                                "\nFirewall ResettingSync Wallet Ban Time\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall resettingsyncwallet:bantime", "0")
                                + HelpExampleCli("firewall resettingsyncwallet:bantime", "10000000")
                                );
        }

        Firewall::ResettingSyncWallet::BanTime = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("resettingsyncwallet-bantime", Firewall::ResettingSyncWallet::BanTime));

        return result;

    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "resettingsyncwallet:disconnect")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall resettingsyncwallet:disconnect \"true|false\"\n"
                                "\nFirewall ResettingSync Wallet Disconnect\n"
                                "\nArguments:\n"
                                "Status: \"true|false\" (bool, required)\n"
                                "\nExamples:\n"
                                + HelpExampleCli("firewall resettingsyncwallet:disconnect", "0")
                                + HelpExampleCli("firewall resettingsyncwallet:disconnect", "10000000")
                                );
        }

        Firewall::ResettingSyncWallet::Disconnect = StringToBool(strArgument1);

        result.push_back(Pair("resettingsyncwallet-disconnect", Firewall::ResettingSyncWallet::Disconnect));

        return result;
    }
    /* ------------------------------------- */

    /* ------------------------------------- */
    if (strSubCommand == "resettingsyncwallet:mincheck")
    {
        if (fHelp || params.size() < 2)
        {
            throw runtime_error("firewall resettingsyncpwallet:mincheck \"seconds\"\n"
                                "\nFirewall ResettingSync Wallet Min Check\n"
                                "\nArguments:\n"
                                "Value: \"seconds\" (integer, required)\n"
                                "\nExamples:\n"
                                "\n0 = default - \n"
                                + HelpExampleCli("firewall resettingsyncwallet:mincheck", "0")
                                + HelpExampleCli("firewall resettingsyncwallet:mincheck", "10000000")
                                );
        }

        Firewall::ResettingSyncWallet::MinCheck = (int)strtod(params[1].get_str().c_str(), NULL);

        result.push_back(Pair("resettingsyncwallet-mincheck", Firewall::ResettingSyncWallet::MinCheck));

        return result;

    }
    /* ------------------------------------- */



    //throw runtime_error("\n");

    return Value::null;


}




/*
   |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
**/