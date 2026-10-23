#include "memory.h"

#include <stdlib.h>
#include <string.h>

#include "bits.h"

static void wipeSaveBuffer(uint8_t* buffer, size_t size)
{
    // Save/restore records can contain KNX Secure keys even when this ETS
    // installation uses plain commissioning. Do not leave a copy on the heap.
    volatile uint8_t* bytes = buffer;
    while (size-- > 0)
        *bytes++ = 0;
}

Memory::Memory(Platform& platform, DeviceObject& deviceObject)
    : _platform(platform), _deviceObject(deviceObject)
{}

Memory::~Memory()
{
    while (_freeList) {
        MemoryBlock* next = _freeList->next;
        delete _freeList;
        _freeList = next;
    }
    while (_usedList) {
        MemoryBlock* next = _usedList->next;
        delete _usedList;
        _usedList = next;
    }
}

void Memory::readMemory()
{
    println("readMemory");

    uint8_t* flashStart = _platform.getNonVolatileMemoryStart();
    size_t flashSize = _platform.getNonVolatileMemorySize();
    if (flashStart == nullptr)
    {
        println("no user flash available;");
        return;
    }

    uint16_t metadataBlockSize = alignToPageSize(_metadataSize);
    if (metadataBlockSize > flashSize)
    {
        println("KNX metadata exceeds non-volatile memory");
        _platform.fatalError();
        return;
    }

    _freeList = new MemoryBlock(flashStart + metadataBlockSize, flashSize - metadataBlockSize);

    uint16_t apiVersion = 0;
    const uint8_t* buffer = popWord(apiVersion, flashStart);

    uint16_t manufacturerId = 0;
    buffer = popWord(manufacturerId, buffer);

    uint8_t hardwareType[LEN_HARDWARE_TYPE] = {0};
    buffer = popByteArray(hardwareType, LEN_HARDWARE_TYPE, buffer);

    uint16_t version = 0;
    buffer = popWord(version, buffer);

    VersionCheckResult versionCheck = FlashAllInvalid;

    // first check correct format of deviceObject-API
    if (_deviceObject.apiVersion == apiVersion) 
    {
        if (_versionCheckCallback != 0) {
            versionCheck = _versionCheckCallback(manufacturerId, hardwareType, version);
            // callback should provide infomation about version check failure reasons
        }
        else if (_deviceObject.manufacturerId() == manufacturerId &&
                 memcmp(_deviceObject.hardwareType(), hardwareType, LEN_HARDWARE_TYPE) == 0) 
        {
            if (_deviceObject.version() == version) {
                versionCheck = FlashValid;
            } 
            else
            {
                versionCheck = FlashTablesInvalid;
            }
        } 
        else 
        {
            println("manufacturerId or hardwareType are different");
            print("expexted manufacturerId: ");
            print(_deviceObject.manufacturerId(), HEX);
            print(", stored manufacturerId: ");
            println(manufacturerId, HEX);
            print("expexted hardwareType: ");
            printHex("", _deviceObject.hardwareType(), LEN_HARDWARE_TYPE);
            print(", stored hardwareType: ");
            printHex("", hardwareType, LEN_HARDWARE_TYPE);
            println("");
        }
    } 
    else 
    {
        println("DataObject api changed, any data stored in flash is invalid.");
        print("expexted DataObject api version: ");
        print(_deviceObject.apiVersion, HEX);
        print(", stored api version: ");
        println(apiVersion, HEX);
    }

    if (versionCheck == FlashAllInvalid)
    {
        println("ETS has to reprogram PA and application!");
        return;
    }

    println("restoring data from flash...");
    print("Restore saveRestores: ");
    println(_saveCount);
    for (int i = 0; i < _saveCount; i++)
    {
        buffer = _saveRestores[i]->restore(buffer);
    }
    println("Restored saveRestores");

#if MASK_VERSION == 0x091A
    if(versionCheck == FlashTablesInvalid)
    {
        println("TableObjects are referring to an older firmware version and are restored, unloaded and filled with 0xff");
    }
#else
    if (versionCheck == FlashTablesInvalid) 
    {
        println("TableObjects are referring to an older firmware version and are not restored");
        return;
    }
#endif
    bool repairedTableReferences = false;
    print("Restore TableObjs: ");
    println(_tableObjCount);
    for (int i = 0; i < _tableObjCount; i++)
    {
        buffer = _tableObjects[i]->restore(buffer);
        uint16_t memorySize = 0;
        buffer = popWord(memorySize, buffer);
        print("Size: ");
        println(memorySize);
        // A new firmware/security profile can grow the serialized metadata
        // over table blocks allocated by an older image. Never admit those
        // blocks to _usedList: unloading them would put protected metadata
        // back into _freeList, where ETS could allocate it again.
        const uint32_t reference = _tableObjects[i]->_data != nullptr
            ? toRelative(_tableObjects[i]->_data) : 0;
        const bool empty = memorySize == 0 && reference == 0 && _tableObjects[i]->_size == 0;
        bool valid = memorySize != 0 && reference != 0 &&
            (reference & 3U) == 0 && (memorySize & 3U) == 0 &&
            _tableObjects[i]->_size != 0 && memorySize >= _tableObjects[i]->_size &&
            applicationMemoryRange(reference, memorySize);
        if (valid)
        {
            const uint8_t* begin = _tableObjects[i]->_data;
            const uint8_t* end = begin + memorySize;
            for (MemoryBlock* used = _usedList; used != nullptr; used = used->next)
                if (begin < used->address + used->size && used->address < end)
                {
                    valid = false;
                    break;
                }
        }
        if (!empty && !valid)
        {
            println("Discarding table reference outside current application memory");
            _tableObjects[i]->_state = LS_UNLOADED;
            _tableObjects[i]->_data = nullptr;
            _tableObjects[i]->_size = 0;
            repairedTableReferences = true;
            continue;
        }
        if (empty)
            continue;

        // this works because TableObject saves a relative addr and restores it itself
        addNewUsedBlock(_tableObjects[i]->_data, memorySize);

#if MASK_VERSION == 0x091A
    	// load the tables but delete the data
        if(versionCheck == FlashTablesInvalid)
        {
            println("unload and fill with 0xff");
            _tableObjects[i]->loadState(LS_UNLOADED);
            uint32_t start = toRelative(_tableObjects[i]->_data);
            uint8_t fillByte = 0xff;
            uint32_t end = start + _tableObjects[i]->_size;
            for(int i = start;i < end;i++)
                writeMemory(i, 1, &fillByte);
        }
#endif
    }
    println("restored TableObjects");
    if (repairedTableReferences)
        writeMemory(); // persist repaired references before another cold boot
}

void Memory::writeMemory()
{
    // first get the necessary size of the writeBuffer
    size_t writeBufferSize = _metadataSize;
    for (int i = 0; i < _saveCount; i++)
        writeBufferSize = MAX(writeBufferSize, _saveRestores[i]->saveSize());

    for (int i = 0; i < _tableObjCount; i++)
        writeBufferSize = MAX(writeBufferSize, _tableObjects[i]->saveSize() + 2 /*for memory pos*/);

    const size_t flashSize = _platform.getNonVolatileMemorySize();
    const size_t metadataBlockSize = alignToPageSize(_metadataSize);
    print("KNX save metadata bytes ");
    print(_metadataSize);
    print(" aligned ");
    print(metadataBlockSize);
    print(" heap buffer bytes ");
    print(writeBufferSize);
    print(" NVM bytes ");
    println(flashSize);
    if (metadataBlockSize > flashSize || writeBufferSize > flashSize || writeBufferSize == 0)
    {
        println("KNX save exceeds non-volatile memory");
        _platform.fatalError();
        return;
    }
    uint8_t* buffer = static_cast<uint8_t*>(malloc(writeBufferSize));
    if (buffer == nullptr)
    {
        println("KNX save heap allocation failed");
        _platform.fatalError();
        return;
    }
    // Every record is bounded independently before it is copied into the
    // platform EEPROM buffer. This also prevents metadata from overwriting
    // the table region when future secure-profile dimensions change.
    auto writeRecord = [&](size_t size, uint32_t& position) -> bool {
        if (size > writeBufferSize || position > metadataBlockSize ||
            size > metadataBlockSize - position || position > flashSize ||
            size > flashSize - position)
            return false;
        position = _platform.writeNonVolatileMemory(position, buffer, size);
        return true;
    };
    uint32_t flashPos = 0;
    uint8_t* bufferPos = buffer;

    bufferPos = pushWord(_deviceObject.apiVersion, bufferPos);
    bufferPos = pushWord(_deviceObject.manufacturerId(), bufferPos);
    bufferPos = pushByteArray(_deviceObject.hardwareType(), LEN_HARDWARE_TYPE, bufferPos);
    bufferPos = pushWord(_deviceObject.version(), bufferPos);

    bool complete = writeRecord(bufferPos - buffer, flashPos);

    print("save saveRestores ");
    println(_saveCount);
    for (int i = 0; complete && i < _saveCount; i++)
    {
        bufferPos = _saveRestores[i]->save(buffer);
        complete = writeRecord(bufferPos - buffer, flashPos);
    }

    print("save tableobjs ");
    println(_tableObjCount);
    for (int i = 0; complete && i < _tableObjCount; i++)
    {
        bufferPos = _tableObjects[i]->save(buffer);

        //save to size of the memoryblock for tableobject too, so that we can rebuild the usedList and freeList
        if (_tableObjects[i]->_data != nullptr)
        {
            MemoryBlock* block = findBlockInList(_usedList, _tableObjects[i]->_data);
            if (block == nullptr)
            {
                println("_data of TableObject not in _usedList");
                wipeSaveBuffer(buffer, writeBufferSize);
                free(buffer);
                _platform.fatalError();
                return;
            }
            bufferPos = pushWord(block->size, bufferPos);
        }
        else
            bufferPos = pushWord(0, bufferPos);

        complete = writeRecord(bufferPos - buffer, flashPos);
    }

    wipeSaveBuffer(buffer, writeBufferSize);
    free(buffer);
    if (!complete)
    {
        println("KNX save metadata record exceeds reserved area");
        _platform.fatalError();
        return;
    }
    _platform.commitNonVolatileMemory();
}

void Memory::saveMemory()
{
    /* Persist table metadata and backing data, not merely a pending platform
       buffer. TableObject invokes this at LE_LOAD_COMPLETED; committing alone
       discarded a direct ETS-style download on the next restart. */
    writeMemory();
}

void Memory::addSaveRestore(SaveRestore* obj)
{
    if (_saveCount >= MAXSAVE - 1)
        return;

    _saveRestores[_saveCount] = obj;
    _saveCount += 1;
    _metadataSize += obj->saveSize();
}

void Memory::addSaveRestore(TableObject* obj)
{
    if (_tableObjCount >= MAXTABLEOBJ)
        return;

    _tableObjects[_tableObjCount] = obj;
    _tableObjCount += 1;
    _metadataSize += obj->saveSize();
    _metadataSize += 2; // for size
}

uint8_t* Memory::allocMemory(size_t size)
{
    // always allocate aligned to pagesize
    size = alignToPageSize(size);

    MemoryBlock* freeBlock = _freeList;
    MemoryBlock* blockToUse = nullptr;
    
    // find the smallest possible block that is big enough
    while (freeBlock)
    {
        const uint32_t start = toRelative(freeBlock->address);
        if (!applicationMemoryRange(start, freeBlock->size))
        {
            println("Invalid free block in application allocator");
            _platform.fatalError();
            return nullptr;
        }
        if (freeBlock->size >= size)
        {
            if (blockToUse != nullptr && (blockToUse->size - size) > (freeBlock->size - size))
                blockToUse = freeBlock;
            else if (blockToUse == nullptr)
                blockToUse = freeBlock;
        }
        freeBlock = freeBlock->next;
    }
    if (!blockToUse)
    {
        println("No available non volatile memory!");
        _platform.fatalError();
    }

    if (blockToUse->size == size)
    {
        // use whole block
        removeFromFreeList(blockToUse);
        addToUsedList(blockToUse);
        return blockToUse->address;
    }
    else
    {
        // split block
        MemoryBlock* newBlock = new MemoryBlock(blockToUse->address, size);
        addToUsedList(newBlock);

        blockToUse->address += size;
        blockToUse->size -= size;

        return newBlock->address;
    }
}


void Memory::freeMemory(uint8_t* ptr)
{
    if (ptr == nullptr || !applicationMemoryRange(toRelative(ptr), 1))
    {
        println("Refusing to free protected or invalid table memory");
        _platform.fatalError();
        return;
    }
    MemoryBlock* block = _usedList;
    MemoryBlock* found = nullptr;
    while (block)
    {
        if (block->address == ptr)
        {
            found = block;
            break;
        }
        block = block->next;
    }
    if(!found)
    {
        println("freeMemory for not used pointer called");
        _platform.fatalError();
    }
    removeFromUsedList(block);
    addToFreeList(block);
    _saveTimeout = millis();
    if (_saveTimeout == 0)
        _saveTimeout = 1; // prevent 0=disabled; no impact by minimal increased timeout
}

bool Memory::applicationMemoryRange(uint32_t relativeAddress, size_t size)
{
    return size != 0 && relativeAddress >= alignToPageSize(_metadataSize) &&
           toAbsoluteChecked(relativeAddress, size) != nullptr;
}

void Memory::writeMemory(uint32_t relativeAddress, size_t size, uint8_t* data)
{
    // EC: bounds-check against the NVM size (wrap-safe) -> a management write (Memory/User/Ext-MemoryWrite),
    // now reachable over the IP tunnel, must never write outside NVM (flash corruption / eeprom-buffer OOB).
    const size_t nvmSize = _platform.getNonVolatileMemorySize();
    if (size > nvmSize || relativeAddress > nvmSize - size)
        return;
    if(_saveTimeout != 0)
    {
        _saveTimeout = millis();
        if (_saveTimeout == 0)
            _saveTimeout = 1; // prevent 0=disabled; no impact by minimal increased timeout
    }
    _platform.writeNonVolatileMemory(relativeAddress, data, size);
}

void Memory::readMemory(uint32_t relativeAddress, size_t size, uint8_t* data)
{
    // EC: same wrap-safe bounds check on the read side (no OOB read of NVM).
    const size_t nvmSize = _platform.getNonVolatileMemorySize();
    if (size > nvmSize || relativeAddress > nvmSize - size)
        return;
    _platform.readNonVolatileMemory(relativeAddress, data, size);
}


uint8_t* Memory::toAbsolute(uint32_t relativeAddress)
{
    return _platform.getNonVolatileMemoryStart() + (ptrdiff_t)relativeAddress;
}

uint8_t* Memory::toAbsoluteChecked(uint32_t relativeAddress, size_t size)
{
    // Wrap-safe NVM bound (same as read/writeMemory): reject an out-of-range range so a management
    // memory-read cannot memcpy past the NVM buffer (OOB read / info-leak). Returns nullptr on reject.
    const size_t nvmSize = _platform.getNonVolatileMemorySize();
    if (size > nvmSize || relativeAddress > nvmSize - size)
        return nullptr;
    return toAbsolute(relativeAddress);
}


uint32_t Memory::toRelative(uint8_t* absoluteAddress)
{
    return absoluteAddress - _platform.getNonVolatileMemoryStart();
}

MemoryBlock* Memory::removeFromList(MemoryBlock* head, MemoryBlock* item)
{
    if (head == item)
    {
        MemoryBlock* newHead = head->next;
        head->next = nullptr;
        return newHead;
    }

    if (!head || !item)
    {
        println("invalid parameters of Memory::removeFromList");
        _platform.fatalError();
    }

    bool found = false;
    MemoryBlock* block = head;
    while (block)
    {
        if (block->next == item)
        {
            found = true;
            block->next = item->next;
            break;
        }
        block = block->next;
    }

    if (!found)
    {
        println("tried to remove block from list not in it");
        _platform.fatalError();
    }
    item->next = nullptr;
    return head;
}

void Memory::removeFromFreeList(MemoryBlock* block)
{
    _freeList = removeFromList(_freeList, block);
}


void Memory::removeFromUsedList(MemoryBlock* block)
{
    _usedList = removeFromList(_usedList, block);
}


void Memory::addToUsedList(MemoryBlock* block)
{
    block->next = _usedList;
    _usedList = block;
}


void Memory::addToFreeList(MemoryBlock* block)
{
    if (_freeList == nullptr)
    {
        _freeList = block;
        return;
    }

    // first insert free block in list
    MemoryBlock* current = _freeList;
    while (current)
    {
        if (current->address <= block->address && (current->next == nullptr || block->address < current->next->address))
        {
            //add after current
            block->next = current->next;
            current->next = block;
            break;
        }
        else if (current->address > block->address)
        {
            //add before current
            block->next = current;

            if (current == _freeList)
                _freeList = block;

            // swap current and block for merge
            MemoryBlock* tmp = current;
            current = block;
            block = tmp;

            break;
        }

        current = current->next;
    }
    // now check if we can merge the blocks
    // first current an block
    if ((current->address + current->size) == block->address)
    {
        current->size += block->size;
        current->next = block->next;
        delete block;
        // check further if now current can be merged with current->next
        block = current;
    }

    // if block is the last one, we are done 
    if (block->next == nullptr)
        return;

    // now check block and block->next
    if ((block->address + block->size) == block->next->address)
    {
        MemoryBlock* merged = block->next;
        block->size += merged->size;
        block->next = merged->next;
        delete merged;
    }
}

uint16_t Memory::alignToPageSize(size_t size)
{
    size_t pageSize = 4; //_platform.flashPageSize(); // align to 32bit for now, as aligning to flash-page-size causes side effects in programming
    // pagesize should be a multiply of two
    return (size + pageSize - 1) & (-1*pageSize);
}

MemoryBlock* Memory::findBlockInList(MemoryBlock* head, uint8_t* address)
{
    while (head != nullptr)
    {
        if (head->address == address)
            return head;

        head = head->next;
    }
    return nullptr;
}

void Memory::addNewUsedBlock(uint8_t* address, size_t size)
{
    if (address == nullptr || !applicationMemoryRange(toRelative(address), size))
    {
        println("Refusing restored table outside application memory");
        _platform.fatalError();
        return;
    }
    MemoryBlock* smallerFreeBlock = _freeList;
    // find block in freeList where the new used block is contained in
    while (smallerFreeBlock)
    {
        if (smallerFreeBlock->next == nullptr ||
            (smallerFreeBlock->next != nullptr && smallerFreeBlock->next->address > address))
            break;
        
        smallerFreeBlock = smallerFreeBlock->next;
    }

    if (smallerFreeBlock == nullptr)
    {
        println("addNewUsedBlock: no smallerBlock found");
        _platform.fatalError();
    }

    if ((smallerFreeBlock->address + smallerFreeBlock->size) < (address + size))
    {
        println("addNewUsedBlock: found block can't contain new block");
        _platform.fatalError();
    }

    if (smallerFreeBlock->address == address && smallerFreeBlock->size == size)
    {
        // we take thow whole block
        removeFromFreeList(smallerFreeBlock);
        addToUsedList(smallerFreeBlock);
        return;
    }

    if (smallerFreeBlock->address == address)
    {
        // we take a front part of the block
        smallerFreeBlock->address += size;
        smallerFreeBlock->size -= size;
    }
    else
    {
        // we take a middle or end part of the block
        uint8_t* oldEndAddr = smallerFreeBlock->address + smallerFreeBlock->size;
        smallerFreeBlock->size = (address - smallerFreeBlock->address);

        if (address + size < oldEndAddr)
        {
            // we take the middle part of the block, so we need a new free block for the end part
            MemoryBlock* newFreeBlock = new MemoryBlock();
            newFreeBlock->next = smallerFreeBlock->next;
            newFreeBlock->address = address + size;
            newFreeBlock->size = oldEndAddr - newFreeBlock->address;
            smallerFreeBlock->next = newFreeBlock;
        }
    }

    MemoryBlock* newUsedBlock = new MemoryBlock(address, size);
    addToUsedList(newUsedBlock);
}

void Memory::versionCheckCallback(VersionCheckCallback func)
{
    _versionCheckCallback = func;
}

VersionCheckCallback Memory::versionCheckCallback()
{
    return _versionCheckCallback;
}

void Memory::loop()
{
    if(_saveTimeout != 0 && millis() - _saveTimeout > 5000)
    {
        println("saveMemory timeout");
        _saveTimeout = 0;
        writeMemory();
    }
}
