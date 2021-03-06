/*
 * Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#ifndef SHARE_VM_GC_SHARED_MODREFBARRIERSET_HPP
#define SHARE_VM_GC_SHARED_MODREFBARRIERSET_HPP

#include "gc/shared/barrierSet.hpp"

// This kind of "BarrierSet" allows a "CollectedHeap" to detect and
// enumerate ref fields that have been modified (since the last
// enumeration), using a card table.

class OopClosure;
class Generation;

class ModRefBarrierSet: public BarrierSet {
protected:
  ModRefBarrierSet(const BarrierSet::FakeRtti& fake_rtti)
    : BarrierSet(fake_rtti.add_tag(BarrierSet::ModRef)) { }
  ~ModRefBarrierSet() { }

public:
  // Causes all refs in "mr" to be assumed to be modified.
  virtual void invalidate(MemRegion mr) = 0;

  // The caller guarantees that "mr" contains no references.  (Perhaps it's
  // objects have been moved elsewhere.)
  virtual void clear(MemRegion mr) = 0;
};

template<>
struct BarrierSet::GetName<ModRefBarrierSet> {
  static const BarrierSet::Name value = BarrierSet::ModRef;
};

#endif // SHARE_VM_GC_SHARED_MODREFBARRIERSET_HPP
