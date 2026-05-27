/*****************************************************************************
LEDBAT Congestion Control Implementation
Based on RFC 6817 - Low Extra Delay Background Transport (LEDBAT)
*****************************************************************************/

#ifndef __LEDBAT_H__
#define __LEDBAT_H__

#include "ccc.h"
#include "packet.h"
#include <vector>
#include <deque>

class LedbatCC : public CCC
{
public:
    LedbatCC();
    virtual ~LedbatCC();

public:
    // CCC interface implementation
    virtual void init();
    virtual void close();
    virtual void onACK(int32_t ackno);
    virtual void onLoss(const int32_t* losslist, int size);
    virtual void onTimeout();
    virtual void onPktSent(const CPacket* pkt);
    virtual void onPktReceived(const CPacket* pkt);

private:
    // RFC 6817 Section 2.4.2 - Core LEDBAT algorithm
    void updateCongestionWindow(const std::vector<int32_t>& delay_samples, int32_t bytes_newly_acked);
    
    // RFC 6817 Section 2.3 - Receiver-side operations
    void processTimestamp(int32_t timestamp);
    
    // RFC 6817 Section 2.4.2 - Required helper functions
    void updateCurrentDelay(int32_t delay);
    void updateBaseDelay(int32_t delay);
    int32_t filterCurrentDelays();              // FILTER() function
    int32_t getMinBaseDelays();                 // MIN(base_delays)
    int64_t roundToMinute(int64_t timestamp);
    void updateCTO();
    
    // Helper functions
    int32_t getCurrentTimestamp();
    int32_t getMinDelay(const std::deque<int32_t>& history);
    
private:
    // RFC 6817 Section 2.5 - Parameter values
    static const int TARGET_DELAY = 100000;    // 100ms in microseconds (TARGET)
    static constexpr double GAIN = 1.0;        // Gain factor
    static const int BASE_HISTORY_SIZE = 10;   // BASE_HISTORY - delay minima over minutes
    static const int CURRENT_FILTER_SIZE = 4;  // CURRENT_FILTER - recent delay samples
    static const int ALLOWED_INCREASE = 1;     // ALLOWED_INCREASE parameter
    static const int INIT_CWND = 2;            // Initial congestion window in MSS
    static const int MIN_CWND = 2;             // Minimum congestion window in MSS
    
    // State variables for RFC 6817 algorithm
    std::deque<int32_t> m_currentDelays;        // CURRENT_FILTER delay measurements
    std::deque<int32_t> m_baseDelays;           // BASE_HISTORY delay minima
    int64_t m_lastRollover;                     // Last time base delay was rolled over
    int32_t m_flightSize;                       // Amount of data outstanding
    int32_t m_CTO;                              // Congestion timeout value
    
    // LEDBAT specific state
    bool m_inSlowStart;                         // Whether in slow start phase
    int32_t m_lastTimeout;                      // Last timeout occurrence
};

#endif // __LEDBAT_H__
