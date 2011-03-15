/*!
 * \file alloc-common.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Debugging facility for alloc.
 *
 * \addtogroup alloc
 * @{
 */
#ifndef _KNOT_ALLOC_COMMON_H_
#define _KNOT_ALLOC_COMMON_H_

#define MEM_DEBUG
#define MEM_NOSLAB
#define MEM_POISON

/* Optimisation macros. */
#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

#ifdef MEM_DEBUG
#define debug_mem(msg...) fprintf(stderr, msg)
#else
#define debug_mem(msg...)
#endif


#endif /* _KNOT_ALLOC_COMMON_H_ */

/*! @} */
