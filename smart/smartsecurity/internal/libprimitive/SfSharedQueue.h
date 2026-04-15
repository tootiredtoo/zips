/**
****************************************************************************************************
* @vd_noapi
* @file SfSharedQueue.h
* @brief Security framework [SF] Template class SharedQueue implementation.
* @author Dmitriy Dorogovtsev (d.dorogovtse@samsung.com)
* @date Created Mar 25, 2013
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

#ifndef _SF_SHARED_QUEUE_H_
#define _SF_SHARED_QUEUE_H_

#include "SfMutex.h"
#include "SfLockGuard.h"
#include "SfConditionVariable.h"

#include <queue>

/**
****************************************************************************************************
* @class SfSharedQueue
* @brief Shared queue with synchronization mechanisms
****************************************************************************************************
*/
template < typename TData >
class SfSharedQueue
{
public: // func
    /**
    ************************************************************************************************
    * @brief	Default constructor
    ************************************************************************************************
    */
    SfSharedQueue()
    : m_bExit(false)
    {
    }

    /**
    ************************************************************************************************
    * @brief	Destructor
    ************************************************************************************************
    */
    ~SfSharedQueue()
    {
    }

    /**
    ************************************************************************************************
    * @brief	Get elevent from the shared queue
    * @param	[out] value element to be returned
    * @return 	SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Front( TData& value )
    {
        SfLockGuard guard( m_mutex );
        if ( m_queue.empty() )
            return SF_STATUS_FAIL;

        value = m_queue.front();
        return SF_STATUS_OK;
    }
	
    /**
    ************************************************************************************************
    * @brief	Remove elevent from the shared queue
    * @param	[out] value element to be returned
    * @return 	SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Pop()
    {
        SfLockGuard guard( m_mutex );
        if ( m_queue.empty() )
            return SF_STATUS_FAIL;

        m_queue.pop();
        return SF_STATUS_OK;
    }

    /**
    ************************************************************************************************
    * @brief	Get and remove elevent from the shared queue
    * @param	[out] value element to be returned
    * @return 	SF_STATUS_OK on success, SF_STATUS_FAIL otherwise
    ************************************************************************************************
    */
    SF_STATUS Pop( TData& value )
    {
        SfLockGuard guard( m_mutex );
        if ( m_queue.empty() )
            return SF_STATUS_FAIL;

        value = m_queue.front();
        m_queue.pop();
        return SF_STATUS_OK;
    }

    /**
    ************************************************************************************************
    * @brief	Get element from the queue with synchronization
    * @param	[out] value element to be returned
    * @return 	void
    ************************************************************************************************
    */
    void WaitPop( TData& value )
    {
        SfLockGuard guard( m_mutex );
        while ( m_queue.empty() )
        {
            m_queueEmptyCond.Wait( m_mutex );
            if (m_bExit == true)
                return;
        }
        if (m_queue.size() > 0)
        {
            value = m_queue.front();
            m_queue.pop();
        }
    }

    /**
    ************************************************************************************************
    * @brief	send signal to WaitPop and exit WaitPop looping.
    * @return 	void
    ************************************************************************************************
    */
    void ExitWaitPop(void)
    {
        m_bExit = true;
        m_queueEmptyCond.NotifyOne();
    }

    /**
    ************************************************************************************************
    * @brief	Push element is the shared queue
    * @param	[in] data element to be pushed to the shared queue
    * return	void
    ************************************************************************************************
    */
    void Push( const TData& data )
    {
        m_mutex.Lock();
        m_queue.push( data );
        m_mutex.Unlock();

        m_queueEmptyCond.NotifyOne();
    }

    /**
    ************************************************************************************************
    * @brief	Check whenever shared queue is empty
    * @return	TRUE if shared queue is empty, FALSE otherwise
    ************************************************************************************************
    */
    Bool IsEmpty()
    {
        SfLockGuard guard( m_mutex );
        return m_queue.empty();
    }

    /**
    ************************************************************************************************
    * @brief	Get size of the Shared queue
    * @return	Size of the shared queue
    ************************************************************************************************
    */
    size_t GetSize()
    {
        SfLockGuard guard( m_mutex );
        return m_queue.size();
    }

    /**
    ************************************************************************************************
    * @brief	Make signal to release pthread_signal_wait
    * @return	void
    ************************************************************************************************
    */
    void MakeSignal(void)
    {
        m_queueEmptyCond.NotifyOne();
    }

    /**
    ************************************************************************************************
    * @brief	Clean std:queue
    * @return	void
    ************************************************************************************************
    */
    void Clean(void)
    {
        SfLockGuard guard( m_mutex );
        std::queue< TData >	empty; 
        std::swap(m_queue, empty);
    }

private: // var

    std::queue< TData >	m_queue;          ///< Queue to store the data of the TData type
    SfMutex             m_mutex;          ///< SfMutex object
    SfConditionVariable	m_queueEmptyCond; ///< SfConditionVariable object
    bool                m_bExit;          // If true, WaitPop will be terminated.
};

#endif /* !_SF_SHARED_QUEUE_H_ */
