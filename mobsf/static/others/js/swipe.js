
class Swipe {
	constructor(elem, options = {}) {
		this.elem = elem;
		this.minDistance = options.minDistance || 100;
		this.maxTime = options.maxTime || 500;
		this.corners = options.corners || false;
		this.addListeners();
		this.events = {
			live:[], 
			after:[]
		};
		Swipe.directions().forEach(direction => this.events[direction] = []);
	}
	
	static directions() {
		return ['left', 'right', 'up', 'down', 'leftup', 'leftdown', 'rightup', 'rightdown'];
	}
	
	static position(e) {
		return {x: e.pageX, y: e.pageY};
	}
	
	static getOffsets(e, startPos) {
		const newPos = Swipe.position(e);
		return {
		  x: newPos.x - startPos.x,
		  y: newPos.y - startPos.y
		};
	}
	
	static getDirections(offsets, corners) {
		const directions = {};
		directions.left  = offsets.x <= 0 ? Math.abs(offsets.x) : 0;
		directions.right = offsets.x >= 0 ? Math.abs(offsets.x) : 0;
		directions.up    = offsets.y <= 0 ? Math.abs(offsets.y) : 0;
		directions.down  = offsets.y >= 0 ? Math.abs(offsets.y) : 0;
			
		if (corners) {
		  directions.leftup    = (Math.abs((directions.left + directions.up))    / 1.5);
		  directions.leftdown  = (Math.abs((directions.left + directions.down))  / 1.5);
		  directions.rightup   = (Math.abs((directions.right + directions.up))   / 1.5);
		  directions.rightdown = (Math.abs((directions.right + directions.down)) / 1.5);
		}
		
		return directions;
	}
	
	static order(directions) {
		return Object.keys(directions).sort((a, b) => directions[b] - directions[a]);
	}
	
	addEventListener(evt, bc) {
		const keys = Object.keys(this.events);
		if (keys.indexOf(evt) !== -1) {
		  this.events[evt].push(bc);
	    const i = this.events.length - 1;
		  return {
		    clear: () => {
			    this.events[i] = undefined;
		    }
	    };
		} else {
			throw new Error("Event is not valid, use " + keys.join(", "));
		}
	}
	
	down(e) {
		//e.preventDefault();
		this.didDown = true;
		this.startTime = Date.now();
		this.startPos = Swipe.position(e);
	}
	
	move(e) {
		//e.preventDefault();
		if (!this.didDown) {
			return;
		}
	  this.didSwipe = true;
		
		if (this.events.live.length > 0) {
		  const offsets  = Swipe.getOffsets(e, this.startPos);
		  const directions = Swipe.getDirections(offsets, this.corners);	
		  const direction = Swipe.order(directions)[0];
	    const distance = directions[direction];
		  this.events.live.forEach(evt => {
		    if (typeof evt === "function") {
		      evt(direction, distance);
		    }
		  });
		}
	}
	
	up(e) {
		//e.preventDefault();
		this.didDown = false;
		if (!this.didSwipe) {
			return;
		}
		this.didSwipe = false;
			
		const elapsedTime = Date.now() - this.startTime;
		if (elapsedTime <= this.maxTime) {
	    const offsets  = Swipe.getOffsets(e, this.startPos);
	    const directions = Swipe.getDirections(offsets, this.corners);	
	    const direction = Swipe.order(directions)[0];
	    const distance = directions[direction];
			
	    if (distance >= this.minDistance) {
			  this.events.after.forEach(evt => {
	        if (typeof evt === "function") {
	          evt(direction, distance);
          }
        });
			  this.events[direction].forEach(evt => {
	        if (typeof evt === "function") {
	          evt(distance);
          }
        });
		  }
	  }				
	}
	
	addListeners() {	
	  this.elem.addEventListener("touchstart", e => this.down(e));
	  this.elem.addEventListener("mousedown", e => this.down(e));
	  this.elem.addEventListener("touchmove", e => this.move(e));
	  document.addEventListener("mousemove", e => this.move(e));
	  this.elem.addEventListener("touchend", e => this.up(e));
	  document.addEventListener("mouseup", e => this.up(e));
	}
}