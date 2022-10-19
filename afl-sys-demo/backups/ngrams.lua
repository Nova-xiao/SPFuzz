description = "Record all the n-grams"
short_description = "N-gram record"
category = "Fuzzing"
args =
{
    {
        name = "store_file", 
		description = "the name of the system call to count", 
		argtype = "string",
        optional = true
    },
    {
        name = "proc_id", 
		description = "the pid(tid) of the process we want to monitor", 
		argtype = "int",
        optional = false
    },
    {
        name = "stride",
        description = "the stride of our n-gram record",
        argtype = "int",
        optional = true
    },
}

require "io"
require "posix"
begin_to_record = false
last_record_index = 0
pipefn = 0
index = 0
count = 0
stride = 1
temp_grams = {"","","","","","","","","","","","","","","",""} 
-- 8-gram needs 16 slots to apply all strides
proc_id = 0
record_table = {}
store_file = "/home/xjf/nGramRecord.lua"

--Argument notification callback
function on_set_arg(name, val)
    if name == "store_file" then
        store_file = val
        print(string.format("We will store all 8-grams to %s", store_file))
        return true
    elseif name == "stride" then
        stride = tonumber(val)
        print(string.format("We will record 8-grams by stride %d", stride))
        if (stride>0) and (stride<=8) then
            return true
        end
    elseif name == "proc_id" then
        proc_id = tonumber(val)
        print(string.format("We will only record syscalls of tid %d", proc_id))
        return true
    end
    
    return false
end

-- Initialization callback
function on_init()
    -- Request the fields needed for this chisel
    fetype = chisel.request_field("evt.type")

    -- set the filter
    -- filter the other same record which is only different in directions
    chisel.set_filter(string.format("evt.dir=> and thread.tid=%d",proc_id ))
    
    return true
end

function on_capture_start()
    --communicate to python that we have init over
    --intend to use pipe first but failed
    io.stderr:write("INIT\n")
    return true
end

-- Event parsing callback
function on_event()
    local evttype = evt.field(fetype)
    temp_grams[index] = evttype
    index = index+1
    -- turn on recording when 8-gram reaches
    if (not begin_to_record) and (index >= 8) then
        begin_to_record = true
        last_record_index = index
    end
    -- if we have started recording
    if begin_to_record then
        local start_index = (index+8)%16
        if ((index+16-last_record_index)%16)%stride==0 then
            -- reach stride, need record
            count = count+1
            -- concat n-grams to one string
            local ngramStr = temp_grams[start_index]
            for i=start_index+1,start_index+7,1 do
                ngramStr = ngramStr..","..temp_grams[i%16]
            end
            if record_table[ngramStr] then
                record_table[ngramStr] = record_table[ngramStr]+1
            else
                -- record_table[ngramStr]==nil, we have a new n-gram
                record_table[ngramStr] = 1
            end
            -- print info of n-grams
            -- print(string.format("Count:%d, N-gram now is:%s",count,ngramStr))
            last_record_index = index
        end
    end
    -- refresh end flag if we have filled a round
    if index == 16 then
        index = 0
    end
    
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
    -- write into file
    print(string.format("Capture End, begin to write %d 8-grams of %d kinds.",count,#record_table))
    file = io.open(store_file, "w+")
    for key,value in pairs(record_table) do
        file:write(string.format("%s %d\n",key,value))
    end
    
end

