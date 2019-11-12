// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2019 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#ifndef COINCONTROL_H
#define COINCONTROL_H

#include "core.h"

/** Coin Control Features. */
class CCoinControl
{
    public:

        CTxDestination destChange;

        bool useDarkSend;
        bool useInstantX;


        CCoinControl()
        {
            SetNull();
        }
            

        void SetNull()
        {
            destChange = CNoDestination();
            setSelected.clear();
            useInstantX = false;
            useDarkSend = false;
        }
        

        bool HasSelected() const
        {
            return (setSelected.size() > 0);
        }
        

        bool IsSelected(const uint256& hash, unsigned int n) const
        {
            COutPoint outpt(hash, n);

            return (setSelected.count(outpt) > 0);
        }
        

        void Select(COutPoint& output)
        {
            setSelected.insert(output);
        }

        
        void UnSelect(COutPoint& output)
        {
            setSelected.erase(output);
        }

        
        void UnSelectAll()
        {
            setSelected.clear();
        }


        void ListSelected(std::vector<COutPoint>& vOutpoints)
        {
            vOutpoints.assign(setSelected.begin(), setSelected.end());
        }

            
    private:


        std::set<COutPoint> setSelected;

};

#endif // COINCONTROL_H
