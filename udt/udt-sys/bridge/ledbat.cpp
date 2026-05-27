/*****************************************************************************
LEDBAT Congestion Control Implementation
Based on RFC 6817 - Low Extra Delay Background Transport (LEDBAT)
Implements sections 2.3 and 2.4 of the RFC
*****************************************************************************/

#include "ledbat.h"
#include <algorithm>
#include <cmath>
#include <climits>

#ifndef WINDOWS
    #include <sys/time.h>
#else
    #include <windows.h>
#endif

LedbatCC::LedbatCC() :
    m_lastRollover(-60000000), // More than a minute in the past
    m_flightSize(0),
    m_CTO(1000000), // 1 second in microseconds
    m_inSlowStart(true),
    m_lastTimeout(0)
{
    // RFC 6817 Section 2.4.2 - Initialize data structures
    // Initialize current_delays list with CURRENT_FILTER elements
    m_currentDelays.clear();
    
    // Initialize base_delays list with BASE_HISTORY elements set to +INFINITY
    m_baseDelays.clear();
    for (int i = 0; i < BASE_HISTORY_SIZE; ++i) {
        m_baseDelays.push_back(INT_MAX);
    }
}

LedbatCC::~LedbatCC()
{
}

void LedbatCC::init()
{
    // RFC 6817 Section 2.4.2 - Initialize congestion window
    m_dCWndSize = INIT_CWND * m_iMSS; // cwnd = INIT_CWND * MSS
    m_inSlowStart = true;
    m_flightSize = 0;
    m_CTO = 1000000; // 1 second in microseconds
    
    // Initialize data structures
    m_currentDelays.clear();
    m_baseDelays.clear();
    for (int i = 0; i < BASE_HISTORY_SIZE; ++i) {
        m_baseDelays.push_back(INT_MAX);
    }
    
    // Get current time for initialization
    int64_t now = getCurrentTimestamp();
    m_lastRollover = now - 60000000; // More than a minute in the past
}

void LedbatCC::close()
{
    // Clean up resources
    m_currentDelays.clear();
    m_baseDelays.clear();
}

void LedbatCC::onACK(int32_t ackno)
{
    // RFC 6817 Section 2.4.2 - Process ACK and update congestion window
    (void)ackno; // Suppress unused parameter warning
    
    // In UDT, delay measurements are handled through onPktReceived
    // The ACK processing here focuses on updating the congestion window
    // based on the delay measurements already collected
    
    // bytes_newly_acked: this ACK acknowledges new data
    // In UDT context, we can assume this ACK acknowledges approximately MSS bytes
    int32_t bytes_newly_acked = m_iMSS;
    
    // Create a vector with recent delay samples for processing
    // In a complete implementation, the delay samples would be embedded in the ACK packet
    // For UDT integration, we process delays as they're received via onPktReceived
    std::vector<int32_t> delay_samples;
    
    // Only process if we have current delay measurements
    if (!m_currentDelays.empty()) {
        // Use the most recent delay measurement(s) 
        delay_samples.push_back(m_currentDelays.back());
        updateCongestionWindow(delay_samples, bytes_newly_acked);
    }
}

void LedbatCC::onLoss(const int32_t* losslist, int size)
{
    // RFC 6817 Section 2.4.2 - on data loss (at most once per RTT)
    (void)losslist; // Suppress unused parameter warning
    (void)size;     // Suppress unused parameter warning
    
    // cwnd = min(cwnd, max(cwnd/2, MIN_CWND * MSS))
    double new_cwnd = std::max(m_dCWndSize / 2.0, double(MIN_CWND * m_iMSS));
    m_dCWndSize = std::min(m_dCWndSize, new_cwnd);
    
    // Exit slow start
    m_inSlowStart = false;
    
    // Update packet sending period based on new window size
    if (m_dCWndSize > 0 && m_iRTT > 0) {
        m_dPktSndPeriod = (double(m_iRTT) / m_dCWndSize);
    }
    
    // Note: if data lost is not to be retransmitted:
    // flightsize = flightsize - bytes_not_to_be_retransmitted
    // This would need to be handled by the caller based on loss list
}

void LedbatCC::onTimeout()
{
    // RFC 6817 Section 2.4.2 - if no ACKs are received within a CTO
    // extreme congestion, or significant RTT change
    // set cwnd to 1MSS and backoff the congestion timer
    m_dCWndSize = 1.0 * m_iMSS;
    m_CTO = 2 * m_CTO;
    
    m_inSlowStart = false;
    m_lastTimeout = getCurrentTimestamp();
    
    // Update packet sending period
    if (m_dCWndSize > 0 && m_iRTT > 0) {
        m_dPktSndPeriod = (double(m_iRTT) / m_dCWndSize);
    }
}

void LedbatCC::onPktSent(const CPacket* pkt)
{
    // RFC 6817 Section 2.3 - Sender adds timestamp to outgoing packets
    // UDT handles the timestamping automatically, we track flight size
    (void)pkt; // Suppress unused parameter warning
    
    // Track flight size - add data sent to outstanding bytes
    // In UDT, each data packet is typically MSS sized
    m_flightSize += m_iMSS;
}

void LedbatCC::onPktReceived(const CPacket* pkt)
{
    // RFC 6817 Section 2.3 - Process received packet timestamps for one-way delay measurement
    // This is where LEDBAT gets its delay samples from received data packets
    if (pkt && pkt->m_iTimeStamp > 0) {
        processTimestamp(pkt->m_iTimeStamp);
    }
}

void LedbatCC::updateCongestionWindow(const std::vector<int32_t>& delay_samples, int32_t bytes_newly_acked)
{
    // RFC 6817 Section 2.4.2 - Complete LEDBAT sender algorithm
    
    // Process each delay sample in the acknowledgement
    for (const auto& delay : delay_samples) {
        updateBaseDelay(delay);
        updateCurrentDelay(delay);
    }
    
    // Calculate queuing delay: FILTER(current_delays) - MIN(base_delays)
    int32_t current_delay_estimate = filterCurrentDelays();
    int32_t base_delay_estimate = getMinBaseDelays();
    
    if (current_delay_estimate < 0 || base_delay_estimate == INT_MAX) {
        return; // Not enough data yet
    }
    
    int32_t queuing_delay = current_delay_estimate - base_delay_estimate;
    queuing_delay = std::max(0, queuing_delay); // Ensure non-negative
    
    // Calculate off_target: (TARGET - queuing_delay) / TARGET
    double off_target = (double(TARGET_DELAY) - queuing_delay) / double(TARGET_DELAY);
    
    // RFC 6817: cwnd += GAIN * off_target * bytes_newly_acked * MSS / cwnd
    double cwnd_increment = GAIN * off_target * bytes_newly_acked * m_iMSS / m_dCWndSize;
    m_dCWndSize += cwnd_increment;
    
    // RFC 6817: max_allowed_cwnd = flightsize + ALLOWED_INCREASE * MSS
    double max_allowed_cwnd = m_flightSize + ALLOWED_INCREASE * m_iMSS;
    m_dCWndSize = std::min(m_dCWndSize, max_allowed_cwnd);
    
    // RFC 6817: cwnd = max(cwnd, MIN_CWND * MSS)
    m_dCWndSize = std::max(m_dCWndSize, double(MIN_CWND * m_iMSS));
    
    // RFC 6817: flightsize = flightsize - bytes_newly_acked
    m_flightSize = std::max(0, m_flightSize - bytes_newly_acked);
    
    // Update CTO
    updateCTO();
    
    // Update packet sending period based on new window size
    if (m_dCWndSize > 0 && m_iRTT > 0) {
        m_dPktSndPeriod = (double(m_iRTT) / m_dCWndSize);
    }
}

void LedbatCC::processTimestamp(int32_t timestamp)
{
    // RFC 6817 Section 2.3 - Receiver-side timestamp processing
    // Calculate one-way delay using received timestamp
    int32_t current_time = getCurrentTimestamp();
    int32_t one_way_delay = current_time - timestamp;
    
    if (one_way_delay > 0) {
        updateCurrentDelay(one_way_delay);
        updateBaseDelay(one_way_delay);
    }
}

// RFC 6817 Section 2.4.2 - update_current_delay()
void LedbatCC::updateCurrentDelay(int32_t delay)
{
    // Maintain a list of CURRENT_FILTER last delays observed
    if (m_currentDelays.size() >= CURRENT_FILTER_SIZE) {
        m_currentDelays.pop_front(); // Delete first item
    }
    m_currentDelays.push_back(delay); // Append delay
}

// RFC 6817 Section 2.4.2 - update_base_delay()
void LedbatCC::updateBaseDelay(int32_t delay)
{
    // Maintain BASE_HISTORY delay-minima
    // Each minimum is measured over a period of a minute
    int64_t now = getCurrentTimestamp();
    
    if (roundToMinute(now) != roundToMinute(m_lastRollover)) {
        m_lastRollover = now;
        m_baseDelays.pop_front(); // Delete first item
        m_baseDelays.push_back(delay); // Append delay
    } else {
        // Update the tail with minimum
        if (!m_baseDelays.empty()) {
            m_baseDelays.back() = std::min(m_baseDelays.back(), delay);
        }
    }
}

// RFC 6817 Section 2.4.2 - FILTER() function
int32_t LedbatCC::filterCurrentDelays()
{
    if (m_currentDelays.empty()) {
        return -1;
    }
    
    // Simple implementation: return the most recent delay
    // Could be enhanced with EWMA, MIN filter, etc.
    return m_currentDelays.back();
}

// RFC 6817 Section 2.4.2 - MIN(base_delays)
int32_t LedbatCC::getMinBaseDelays()
{
    if (m_baseDelays.empty()) {
        return INT_MAX;
    }
    
    return *std::min_element(m_baseDelays.begin(), m_baseDelays.end());
}

int64_t LedbatCC::roundToMinute(int64_t timestamp)
{
    // Round timestamp to minute boundary
    return (timestamp / 60000000) * 60000000;
}

void LedbatCC::updateCTO()
{
    // RFC 6817 - Implements RTT estimation mechanism
    // For simplicity, we'll use a basic implementation
    // In a full implementation, this would follow RFC 6298
    
    // Update CTO based on RTT measurements
    if (m_iRTT > 0) {
        m_CTO = std::max(1000000, m_iRTT * 2); // At least 1 second
    }
}

int32_t LedbatCC::getCurrentTimestamp()
{
    // Get current timestamp in microseconds
    #ifndef WINDOWS
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return tv.tv_sec * 1000000 + tv.tv_usec;
    #else
        LARGE_INTEGER freq, counter;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&counter);
        return (int32_t)((counter.QuadPart * 1000000) / freq.QuadPart);
    #endif
}

int32_t LedbatCC::getMinDelay(const std::deque<int32_t>& history)
{
    if (history.empty()) {
        return INT_MAX;
    }
    
    return *std::min_element(history.begin(), history.end());
}
