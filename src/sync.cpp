// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2009-2012 The Darkcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013 Novacoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015 The Crave developers
// Copyright (c) 2017 XUVCoin developers
// Copyright (c) 2018-2020 Profit Hunters Coin developers

// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php


#include "sync.h"

#include "util.h"


#ifdef DEBUG_LOCKCONTENTION
void PrintLockContention(const char* pszName, const char* pszFile, int nLine)
{
    if (fDebug)
    {
        LogPrint("sync", "%s : NOTICE - LOCKCONTENTION: %s\n", __FUNCTION__, pszName);
        LogPrint("sync", "%s : NOTICE - Locker: %s:%d\n", __FUNCTION__, pszFile, nLine);
    }
}
#endif /* DEBUG_LOCKCONTENTION */

#ifdef DEBUG_LOCKORDER
//
// Early deadlock detection.
// Problem being solved:
//    Thread 1 locks  A, then B, then C
//    Thread 2 locks  D, then C, then A
//     --> may result in deadlock between the two threads, depending on when they run.
// Solution implemented here:
// Keep track of pairs of locks: (A before B), (A before C), etc.
// Complain if any thread tries to lock in a different order.
//

struct CLockLocation
{
    CLockLocation(const char* pszName, const char* pszFile, int nLine)
    {
        mutexName = pszName;
        sourceFile = pszFile;
        sourceLine = nLine;
    }

    std::string ToString() const
    {
        return mutexName+"  "+sourceFile+":"+itostr(sourceLine);
    }

    std::string MutexName() const
    {
        return mutexName;
    }

    private:

        std::string mutexName;
        std::string sourceFile;
        int sourceLine;
};


typedef std::vector< std::pair<void*, CLockLocation> > LockStack;

static boost::mutex dd_mutex;
static std::map<std::pair<void*, void*>, LockStack> lockorders;
static boost::thread_specific_ptr<LockStack> lockstack;


static void potential_deadlock_detected(const std::pair<void*, void*>& mismatch, const LockStack& s1, const LockStack& s2)
{
    if (fDebug)
    {
        LogPrint("sync", "%s : WARNING - POTENTIAL DEADLOCK DETECTED \n", __FUNCTION__);
        
        LogPrint("sync", "%s : WARNING - Previous lock order was: \n", __FUNCTION__);
    }

    for(const PAIRTYPE(void*, CLockLocation)& i: s2)
    {
        if (i.first == mismatch.first)
        {
            if (fDebug)
            {
                LogPrint("sync", "%s : (1)", __FUNCTION__);
            }
        }

        if (i.first == mismatch.second)
        {
            if (fDebug)
            {
                LogPrint("sync", "%s : (2)", __FUNCTION__)
            }
        }

        if (fDebug)
        {
            LogPrint("sync", "%s : NOTICE - %s\n", __FUNCTION__, i.second.ToString());
        }
    }
    
    if (fDebug)
    {
        LogPrint("sync", "%s : COK - Current lock order is: \n", __FUNCTION__);
    }

    for(const PAIRTYPE(void*, CLockLocation)& i: s1)
    {
        if (i.first == mismatch.first)
        {
            if (fDebug)
            {
                LogPrint("sync", "%s : (1)", __FUNCTION__);
            }
        }

        if (i.first == mismatch.second)
        {
            if (fDebug)
            {
                LogPrint("sync", "%s : (2)", __FUNCTION__);
            }
        }

        if (fDebug)
        {
            LogPrint("sync", "%s : NOTICE - %s \n", __FUNCTION__, i.second.ToString());
        }
    }
}


static void push_lock(void* c, const CLockLocation& locklocation, bool fTry)
{
    if (lockstack.get() == NULL)
    {
        lockstack.reset(new LockStack);
    }

    if (fDebug)
    {
        LogPrint("lock", "%s : NOTICE - Locking: %s \n", __FUNCTION__, locklocation.ToString());
    }

    dd_mutex.lock();

    (*lockstack).push_back(std::make_pair(c, locklocation));

    if (!fTry)
    {
        for(const PAIRTYPE(void*, CLockLocation)& i: (*lockstack))
        {
            if (i.first == c)
            {
                break;
            }

            std::pair<void*, void*> p1 = std::make_pair(i.first, c);

            if (lockorders.count(p1))
            {
                continue;
            }

            lockorders[p1] = (*lockstack);

            std::pair<void*, void*> p2 = std::make_pair(c, i.first);

            if (lockorders.count(p2))
            {
                potential_deadlock_detected(p1, lockorders[p2], lockorders[p1]);

                break;
            }
        }
    }
    dd_mutex.unlock();
}


static void pop_lock()
{
    const CLockLocation& locklocation = (*lockstack).rbegin()->second;

    if (fDebug)
    {
        LogPrint("lock", "%s : OK - Unlocked: %s \n", __FUNCTION__, locklocation.ToString());
    }

    dd_mutex.lock();

    (*lockstack).pop_back();
    
    dd_mutex.unlock();
}


void EnterCritical(const char* pszName, const char* pszFile, int nLine, void* cs, bool fTry)
{
    push_lock(cs, CLockLocation(pszName, pszFile, nLine), fTry);
}


void LeaveCritical()
{
    pop_lock();
}


std::string LocksHeld()
{
    std::string result;

    for(const PAIRTYPE(void*, CLockLocation)&i: *lockstack)
    {
        result += i.second.ToString() + std::string("\n");
    }

    return result;
}


void AssertLockHeldInternal(const char *pszName, const char* pszFile, int nLine, void *cs)
{
    for(const PAIRTYPE(void*, CLockLocation)&i: *lockstack)
    {
        if (i.first == cs)
        {
            return;
        }
    }

    if (fDebug)
    {
        fprintf(stderr, "%s : ERROR - Assertion failed: lock %s not held in %s:%i; locks held: \n %s", __FUNCTION__, pszName, pszFile, nLine, LocksHeld().c_str());
    }
    
    abort();
}

#endif /* DEBUG_LOCKORDER */
