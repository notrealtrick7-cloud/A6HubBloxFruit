-- A6 Obf Alpha 2.8 | TRUE VM / PAGED RUNTIME
-- No loadstring/load. No source reconstruction. No anti-debug/evasion.
-- Expects an offline-compiled authenticated A6VM28 container in
-- _G.__A6_VM28_CONTAINER and its root/session key in _G.__A6_VM28_KEY.

local VM_VERSION=0x0208
local MAGIC="A6VM"
local MAX_STEPS=4000000
local MAX_BLOCKS=65535
local MAX_BLOCK_BYTES=1024*1024
local MAX_CONST_BYTES=512*1024
local OP={HALT=0,LOADK=1,MOVE=2,GETGLOBAL=3,SETGLOBAL=4,GETTABLE=5,SETTABLE=6,ADD=7,SUB=8,MUL=9,DIV=10,MOD=11,UNM=12,NOT=13,EQ=14,LT=15,LE=16,JMP=17,JMPIF=18,JMPIFNOT=19,CALL=20,RETURN=21,NEWTABLE=22,CONCAT=23,LEN=26,TEST=27,CFG=31}
local function fail(x) error("A6VM28: "..tostring(x),0) end
local bit=bit32
local function ror(x,n)return bit.bor(bit.rshift(x,n),bit.lshift(x,32-n))end
local K={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66b,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a5,0xa81a664b,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}
local function sha256(m)
 local h={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}; local bits=#m*8;m=m.."\128";while #m%64~=56 do m=m.."\0" end;m=m..string.char(0,0,0,0,math.floor(bits/16777216)%256,math.floor(bits/65536)%256,math.floor(bits/256)%256,bits%256)
 for base=1,#m,64 do local w={};for i=0,15 do local p=base+i*4;w[i]=string.byte(m,p)*16777216+string.byte(m,p+1)*65536+string.byte(m,p+2)*256+string.byte(m,p+3) end;for i=16,63 do local a=w[i-15];local b=w[i-2];w[i]=(w[i-16]+bit.bxor(ror(a,7),ror(a,18),bit.rshift(a,3))+w[i-7]+bit.bxor(ror(b,17),ror(b,19),bit.rshift(b,10)))%4294967296 end;local a,b,c,d,e,f,g,z=table.unpack(h);for i=0,63 do local s1=bit.bxor(ror(e,6),ror(e,11),ror(e,25));local ch=bit.bxor(bit.band(e,f),bit.band(bit.bnot(e),g));local t1=(z+s1+ch+K[i+1]+w[i])%4294967296;local s0=bit.bxor(ror(a,2),ror(a,13),ror(a,22));local maj=bit.bxor(bit.band(a,b),bit.band(a,c),bit.band(b,c));local t2=(s0+maj)%4294967296;z=g;g=f;f=e;e=(d+t1)%4294967296;d=c;c=b;b=a;a=(t1+t2)%4294967296 end;h[1]=(h[1]+a)%4294967296;h[2]=(h[2]+b)%4294967296;h[3]=(h[3]+c)%4294967296;h[4]=(h[4]+d)%4294967296;h[5]=(h[5]+e)%4294967296;h[6]=(h[6]+f)%4294967296;h[7]=(h[7]+g)%4294967296;h[8]=(h[8]+z)%4294967296 end
 local o={};for i=1,8 do local x=h[i];o[#o+1]=string.char(math.floor(x/16777216)%256,math.floor(x/65536)%256,math.floor(x/256)%256,x%256) end;return table.concat(o)
end
local function u32(n)return string.char(math.floor(n/16777216)%256,math.floor(n/65536)%256,math.floor(n/256)%256,n%256)end
local function hmac(k,m)if #k>64 then k=sha256(k)end;k=k..string.rep("\0",64-#k);local i,o={},{ };for n=1,64 do local b=string.byte(k,n);i[n]=string.char(bit.bxor(b,0x36));o[n]=string.char(bit.bxor(b,0x5c))end;return sha256(table.concat(o)..sha256(table.concat(i)..m))end
local function kdf(root,nonce,index,domain)return hmac(root,(domain or "A6VM28")..nonce..u32(index))end
local function xorstream(data,key)local out={};local p=1;local ctr=0;while p<=#data do local b=hmac(key,u32(ctr));local n=math.min(#b,#data-p+1);for i=1,n do out[p+i-1]=string.char(bit.bxor(string.byte(data,p+i-1),string.byte(b,i)))end;p=p+n;ctr=ctr+1 end;return table.concat(out)end
local function rd32(s,p)return string.byte(s,p)*16777216+string.byte(s,p+1)*65536+string.byte(s,p+2)*256+string.byte(s,p+3),p+4 end
local function consts(raw)local out={};local p=1;while p<=#raw do local t=string.byte(raw,p);p=p+1;if t==0 then out[#out+1]=nil elseif t==1 then out[#out+1]=false elseif t==2 then out[#out+1]=true elseif t==3 then local q=s:find("\0",p,true) if not q then fail("number")end;out[#out+1]=tonumber(raw:sub(p,q-1));p=q+1 elseif t==4 then local n; n,p=rd32(raw,p);out[#out+1]=raw:sub(p,p+n-1);p=p+n else fail("constant tag")end end;return out end
local function code(raw)local o={};if #raw%20~=0 then fail("instruction alignment")end;for p=1,#raw,20 do local a;local op=string.byte(raw,p);a=select(1,rd32(raw,p+1));local b=select(1,rd32(raw,p+5));local c=select(1,rd32(raw,p+9));local k=select(1,rd32(raw,p+13));o[#o+1]={op,a,b,c,k}end;return o end
local function release(s)s.currentBlock=nil;s.currentConstPage=nil;s.currentBlockId=nil;s.currentConstId=nil end
local function crypt(c,root,kind,id)local list=kind=="code" and c.blocks or c.constPages;local x=list[id];if not x then fail("missing page")end;local aad=MAGIC.."|"..VM_VERSION.."|"..kind.."|"..id.."|"..#x.data.."|"..(c.metadata or "");local key=kdf(root,x.nonce,id,kind);if hmac(key,aad..x.nonce..x.data)~=x.tag then fail("authentication failure")end;return xorstream(x.data,key)end
local function run(c,root,env)
 if type(c)~="table" or c.magic~=MAGIC or c.version~=VM_VERSION then fail("invalid container")end;if #c.blocks>MAX_BLOCKS then fail("too many blocks")end;if type(root)~="string" or #root<16 then fail("invalid key")end
 local s={container=c,rootKey=root,env=env or _ENV,regs={},pc=1,blockId=c.entry,steps=0};local function loadConst(id)if s.currentConstId~=id then release(s);local raw=crypt(c,root,"const",id);if #raw>MAX_CONST_BYTES then fail("const page too large")end;s.currentConstPage={};local p=1;while p<=#raw do local t=string.byte(raw,p);p=p+1;if t==0 then s.currentConstPage[#s.currentConstPage+1]=nil elseif t==1 then s.currentConstPage[#s.currentConstPage+1]=false elseif t==2 then s.currentConstPage[#s.currentConstPage+1]=true elseif t==3 then local q=raw:find("\0",p,true);s.currentConstPage[#s.currentConstPage+1]=tonumber(raw:sub(p,q-1));p=q+1 elseif t==4 then local n;n,p=rd32(raw,p);s.currentConstPage[#s.currentConstPage+1]=raw:sub(p,p+n-1);p=p+n end end;s.currentConstId=id end end;local function cv(id,slot)loadConst(id);return s.currentConstPage[slot+1]end;local function block(id)if s.currentBlockId==id then return end;release(s);local raw=crypt(c,root,"code",id);if #raw>MAX_BLOCK_BYTES then fail("code block too large")end;s.currentBlock=code(raw);s.currentBlockId=id end;local function jump(id,pc)if id<1 or id>#c.blocks then fail("bad CFG edge")end;s.blockId=id;s.pc=pc or 1;block(id)end
 block(s.blockId)
 while true do s.steps=s.steps+1;if s.steps>MAX_STEPS then fail("step budget")end;local i=s.currentBlock[s.pc];if not i then local n=c.edges and c.edges[s.blockId];if not n then fail("missing CFG edge")end;jump(n,1);i=s.currentBlock[s.pc]end;s.pc=s.pc+1;local op,a,b,d,k=table.unpack(i)
  if op==OP.HALT then release(s);return elseif op==OP.LOADK then s.regs[a]=cv(b,k) elseif op==OP.MOVE then s.regs[a]=s.regs[b] elseif op==OP.GETGLOBAL then s.regs[a]=s.env[cv(b,k)] elseif op==OP.SETGLOBAL then s.env[cv(b,k)]=s.regs[a] elseif op==OP.GETTABLE then s.regs[a]=s.regs[b][s.regs[d]] elseif op==OP.SETTABLE then s.regs[a][s.regs[b]]=s.regs[d] elseif op==OP.ADD then s.regs[a]=s.regs[b]+s.regs[d] elseif op==OP.SUB then s.regs[a]=s.regs[b]-s.regs[d] elseif op==OP.MUL then s.regs[a]=s.regs[b]*s.regs[d] elseif op==OP.DIV then s.regs[a]=s.regs[b]/s.regs[d] elseif op==OP.MOD then s.regs[a]=s.regs[b]%s.regs[d] elseif op==OP.UNM then s.regs[a]=-s.regs[b] elseif op==OP.NOT then s.regs[a]=not s.regs[b] elseif op==OP.EQ then s.regs[a]=s.regs[b]==s.regs[d] elseif op==OP.LT then s.regs[a]=s.regs[b]<s.regs[d] elseif op==OP.LE then s.regs[a]=s.regs[b]<=s.regs[d] elseif op==OP.JMP then s.pc=s.pc+k elseif op==OP.JMPIF and s.regs[a] then s.pc=s.pc+k elseif op==OP.JMPIFNOT and not s.regs[a] then s.pc=s.pc+k elseif op==OP.NEWTABLE then s.regs[a]={} elseif op==OP.CONCAT then s.regs[a]=tostring(s.regs[b])..tostring(s.regs[d]) elseif op==OP.LEN then s.regs[a]=#s.regs[b] elseif op==OP.CALL then local f=s.regs[a];if type(f)~="function" then fail("CALL target")end;s.regs[a]=f(s.regs[b],s.regs[d],k) elseif op==OP.RETURN then local r=s.regs[a];release(s);return r elseif op==OP.TEST then if (s.regs[a] and 1 or 0)~=b then s.pc=s.pc+k end elseif op==OP.CFG then jump(a,b) else fail("bad opcode")end
 end
end

local container=_G.__A6_VM28_CONTAINER
local key=_G.__A6_VM28_KEY
if not container then fail("no compiled A6 container supplied") end
run(container,key,{game=game,workspace=workspace,task=task,math=math,string=string,table=table,coroutine=coroutine,CFrame=CFrame,Vector3=Vector3,Instance=Instance})
